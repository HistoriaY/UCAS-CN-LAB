#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;
// critical section lcok
#define LOCK pthread_mutex_lock(&nat.lock)
// critical section unlcok
#define UNLOCK pthread_mutex_unlock(&nat.lock)

//--------------------------------------------------------------//
// start my added help func
// there was once a bug, hash value can only depend on remote!!!
static u8 nat_hash_val(u32 remote_ip, u16 remote_port)
{
	u8 res = 0;
	res ^= hash8((void *)&remote_ip, 4);
	res ^= hash8((void *)&remote_port, 2);
	return res;
}

// LOCK: apply a new external port
static u16 apply_external_port()
{
	LOCK;
	for (int i = NAT_PORT_MIN; i <= NAT_PORT_MAX; ++i)
	{
		if (!nat.assigned_ports[i])
		{
			nat.assigned_ports[i] = 1;
			{
				UNLOCK;
				return i;
			}
		}
	}
	UNLOCK;
	return 0;
}

// LOCK
static struct nat_mapping *nat_mapping_lookup(u32 remote_ip, u16 remote_port, u32 nat_ip, u16 nat_port, int dir)
{
	LOCK;
	u8 hash_val = nat_hash_val(remote_ip, remote_port);
	struct nat_mapping *entry;
	if (dir == DIR_IN)
	{
		list_for_each_entry(entry, &nat.nat_mapping_list[hash_val], list)
		{
			if (entry->remote_ip == remote_ip && entry->remote_port == remote_port &&
				entry->external_ip == nat_ip && entry->external_port == nat_port)
			{
				UNLOCK;
				return entry;
			}
		}
	}
	else if (dir == DIR_OUT)
	{
		list_for_each_entry(entry, &nat.nat_mapping_list[hash_val], list)
		{
			if (entry->remote_ip == remote_ip && entry->remote_port == remote_port &&
				entry->internal_ip == nat_ip && entry->internal_port == nat_port)
			{
				UNLOCK;
				return entry;
			}
		}
	}
	UNLOCK;
	return NULL;
}

// init a new nat_mapping
static struct nat_mapping *init_nat_mapping(u32 remote_ip, u16 remote_port, u32 nat_ip, u16 nat_port, int dir)
{
	u8 hash_val = nat_hash_val(remote_ip, remote_port);
	if (dir == DIR_IN)
	{
		// lookup dnat rule
		struct dnat_rule *rule, *match_rule = NULL;
		list_for_each_entry(rule, &nat.rules, list)
		{
			if (rule->external_ip == nat_ip && rule->external_port == nat_port)
			{
				match_rule = rule;
				break;
			}
		}
		// no such rule, not allow init
		if (!match_rule)
			return NULL;

		// malloc a new nat_mapping
		struct nat_mapping *new_mapping = malloc(sizeof(struct nat_mapping));
		memset(new_mapping, 0, sizeof(struct nat_mapping));
		new_mapping->remote_ip = remote_ip;
		new_mapping->remote_port = remote_port;
		new_mapping->internal_ip = match_rule->internal_ip;
		new_mapping->internal_port = match_rule->internal_port;
		new_mapping->external_ip = match_rule->external_ip;
		new_mapping->external_port = match_rule->external_port;
		list_add_tail(&new_mapping->list, &nat.nat_mapping_list[hash_val]);
		return new_mapping;
	}
	else if (dir == DIR_OUT)
	{
		// apply a new external port
		u16 new_external_port = apply_external_port();
		log(DEBUG, "new external port: %d", new_external_port);
		// no remain external port -> fail
		if (new_external_port == 0)
		{
			log(DEBUG, "no remain external port");
			return NULL;
		}

		// malloc a new nat_mapping
		struct nat_mapping *new_mapping = malloc(sizeof(struct nat_mapping));
		memset(new_mapping, 0, sizeof(struct nat_mapping));
		new_mapping->remote_ip = remote_ip;
		new_mapping->remote_port = remote_port;
		new_mapping->internal_ip = nat_ip;
		new_mapping->internal_port = nat_port;
		new_mapping->external_ip = nat.external_iface->ip;
		new_mapping->external_port = new_external_port;
		list_add_tail(&new_mapping->list, &nat.nat_mapping_list[hash_val]);
		log(DEBUG, "get new nat mapping");
		return new_mapping;
	}
	return NULL;
}
// end my added help func
//--------------------------------------------------------------//

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list)
	{
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	// fprintf(stdout, "TODO: determine the direction of this packet.\n");

	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
	u32 saddr = ntohl(ip_hdr->saddr);
	u32 daddr = ntohl(ip_hdr->daddr);
	rt_entry_t *s_entry = longest_prefix_match(saddr);
	rt_entry_t *d_entry = longest_prefix_match(daddr);
	iface_info_t *s_iface = s_entry->iface;
	iface_info_t *d_iface = d_entry->iface;
	if (s_iface == nat.external_iface && daddr == nat.external_iface->ip)
		return DIR_IN;
	if (s_iface == nat.internal_iface && d_iface == nat.external_iface)
		return DIR_OUT;
	return DIR_INVALID;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	// fprintf(stdout, "TODO: do translation for this packet.\n");

	log(DEBUG, "Doing translation");

	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
	struct tcphdr *tcp_hdr = (void *)IP_DATA(ip_hdr);

	u32 remote_ip, nat_ip;	   // nat_ip = internal_ip or external_ip;
	u16 remote_port, nat_port; // nat_port = internal_port or external_port;

	if (dir == DIR_IN)
	{
		remote_ip = ntohl(ip_hdr->saddr);
		remote_port = ntohs(tcp_hdr->sport);
		nat_ip = ntohl(ip_hdr->daddr);
		nat_port = ntohs(tcp_hdr->dport);
	}
	else if (dir == DIR_OUT)
	{
		remote_ip = ntohl(ip_hdr->daddr);
		remote_port = ntohs(tcp_hdr->dport);
		nat_ip = ntohl(ip_hdr->saddr);
		nat_port = ntohs(tcp_hdr->sport);
	}

	// look up nat_mapping
	log(DEBUG, "look up nat_mapping");
	struct nat_mapping *entry = nat_mapping_lookup(remote_ip, remote_port, nat_ip, nat_port, dir);
	// entry not exist
	// try to init a new mapping
	if (!entry && (tcp_hdr->flags & TCP_SYN))
	{
		log(DEBUG, "try to init a new mapping");
		entry = init_nat_mapping(remote_ip, remote_port, nat_ip, nat_port, dir);
	}
	// entry still not exist
	if (!entry)
	{
		log(DEBUG, "entry still not exist");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return;
	}

	log(DEBUG, "get entry");

	// pkt->conn update entry->conn
	u32 pkt_seq_end = tcp_seq_end(ip_hdr, tcp_hdr);
	u32 pkt_ack = ntohl(tcp_hdr->ack);

	if (dir == DIR_IN)
	{
		// rewrite ip_hdr and tcp_hdr
		ip_hdr->daddr = htonl(entry->internal_ip);
		tcp_hdr->dport = htons(entry->internal_port);
		// entry->conn
		entry->conn.external_seq_end = pkt_seq_end;
		entry->conn.external_ack = pkt_ack;
		if (tcp_hdr->flags & TCP_FIN)
			entry->conn.external_fin = 1;
	}
	else if (dir == DIR_OUT)
	{
		// rewrite ip_hdr and tcp_hdr
		ip_hdr->saddr = htonl(entry->external_ip);
		tcp_hdr->sport = htons(entry->external_port);
		// entry->conn
		entry->conn.internal_seq_end = pkt_seq_end;
		entry->conn.internal_ack = pkt_ack;
		if (tcp_hdr->flags & TCP_FIN)
			entry->conn.internal_fin = 1;
	}

	// entry->update_time
	entry->update_time = time(NULL);

	// recalculate checksum
	ip_hdr->checksum = ip_checksum(ip_hdr);
	tcp_hdr->checksum = tcp_checksum(ip_hdr, tcp_hdr);

	// forward IP datagram
	log(DEBUG, "forward IP datagram");
	ip_forward_packet(packet, len);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID)
	{
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return;
	}

	log(DEBUG, "direction:%d", dir);

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP)
	{
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
	return (conn->internal_fin && conn->external_fin) &&
		   (conn->internal_ack >= conn->external_seq_end) &&
		   (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while (1)
	{
		// fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		sleep(1);
		LOCK;
		time_t now = time(NULL);
		for (int i = 0; i < HASH_8BITS; ++i)
		{
			struct nat_mapping *entry, *q;
			list_for_each_entry_safe(entry, q, &nat.nat_mapping_list[i], list)
			{
				if (is_flow_finished(&entry->conn) || (int)(now - entry->update_time) >= TCP_ESTABLISHED_TIMEOUT)
				{
					nat.assigned_ports[entry->external_port] = 0;
					list_delete_entry(&entry->list);
					free(entry);
				}
			}
		}
		UNLOCK;
	}
	return NULL;
}

int parse_config(const char *filename)
{
	FILE *conf_file = fopen(filename, "r");
	if (conf_file == NULL)
	{
		log(ERROR, "can not open config file");
		return 1;
	}

	char buff[100];
	char name[16];

	printf("nat config:\n");
	while (fgets(buff, sizeof(buff), conf_file))
	{
		char *pos = strchr(buff, ':');
		if (pos == NULL)
			continue;

		*pos = '\0';
		char *value = pos + 2;

		if (strcmp(buff, "internal-iface") == 0)
		{
			sscanf(value, "%s", name);
			nat.internal_iface = if_name_to_iface(name);
			if (nat.internal_iface)
				printf("internal-iface: %s\n", nat.internal_iface->name);
		}
		else if (strcmp(buff, "external-iface") == 0)
		{
			sscanf(value, "%s", name);
			nat.external_iface = if_name_to_iface(name);
			if (nat.external_iface)
				printf("external-iface: %s\n", nat.external_iface->name);
		}
		else if (strcmp(buff, "dnat-rules") == 0)
		{
			log(DEBUG, "parse a dnat-rule");
			u32 out_ip, in_ip;
			u16 out_port, in_port;
			int rs = sscanf(value, IP_FMT ":%hu %*s " IP_FMT ":%hu", HOST_IP_SCAN_STR(out_ip), &out_port, HOST_IP_SCAN_STR(in_ip), &in_port);
			if (rs < 10)
			{
				log(ERROR, "dnat-rules format error");
				continue;
			}
			struct dnat_rule *rule = malloc(sizeof(struct dnat_rule));
			rule->external_ip = out_ip;
			rule->external_port = out_port;
			rule->internal_ip = in_ip;
			rule->internal_port = in_port;
			list_add_tail(&rule->list, &nat.rules);
			printf("dnat-rules: " IP_FMT ":%hu -> " IP_FMT ":%hu\n", HOST_IP_FMT_STR(out_ip), out_port, HOST_IP_FMT_STR(in_ip), in_port);
		}
		else
			log(ERROR, "error config format : %s", buff);
	}
	fclose(conf_file);
	log(DEBUG, "config loaded");
	return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	// fprintf(stdout, "TODO: release all resources allocated.\n");

	LOCK;
	for (int i = 0; i < HASH_8BITS; i++)
	{
		struct nat_mapping *entry = NULL, *entry_q = NULL;
		list_for_each_entry_safe(entry, entry_q, &nat.nat_mapping_list[i], list)
		{
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	UNLOCK;
	pthread_kill(nat.thread, SIGTERM);
}
