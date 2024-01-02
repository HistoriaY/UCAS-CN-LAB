#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list)
	{
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list)
		{
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	// fprintf(stderr, "TODO: lookup ip address in arp cache.\n");

	pthread_mutex_lock(&arpcache.lock);
	for (int i = 0; i < MAX_ARP_SIZE; ++i)
	{
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4)
		{
			memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	// fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");

	struct cached_pkt *new_cached_packet = malloc(sizeof(struct cached_pkt));
	new_cached_packet->packet = packet;
	new_cached_packet->len = len;

	pthread_mutex_lock(&arpcache.lock);

	bool found = false;
	struct arp_req *req_entry;
	// if there is already a req_entry with the same IP address and iface
	// (which means the corresponding arp request has been sent out)
	list_for_each_entry(req_entry, &arpcache.req_list, list)
	{
		if (req_entry->ip4 == ip4 && req_entry->iface == iface)
		{
			found = true;
			break;
		}
	}

	if (!found)
	{
		// malloc a new req_entry
		req_entry = malloc(sizeof(struct arp_req));
		list_add_tail(&req_entry->list, &arpcache.req_list);
		req_entry->iface = iface;
		req_entry->ip4 = ip4;
		req_entry->sent = time(NULL);
		req_entry->retries = 0;
		init_list_head(&req_entry->cached_packets); // init list head of cached_packets
		arp_send_request(iface, ip4);				// send arp request
	}

	// append packet at the tail of corresponding entry
	list_add_tail(&new_cached_packet->list, &req_entry->cached_packets);

	pthread_mutex_unlock(&arpcache.lock);
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	// fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets.\n");

	pthread_mutex_lock(&arpcache.lock);

	// insert the IP->mac mapping into arpcache
	int pos;
	bool find_same = false;
	bool find_invalid = false;
	// find same entry
	for (int i = 0; i < MAX_ARP_SIZE; ++i)
	{
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4)
		{
			pos = i;
			find_same = true;
			break;
		}
	}
	if (!find_same)
	{
		// find invalid entry
		for (int i = 0; i < MAX_ARP_SIZE; ++i)
		{
			if (!arpcache.entries[i].valid)
			{
				pos = i;
				find_invalid = true;
				break;
			}
		}
	}
	// no same and no place -> random delete an existing entry
	if (!find_same && !find_invalid)
		pos = rand() % MAX_ARP_SIZE;

	// update(same) or inerst(no same) corresponding entry
	if (find_same)
		arpcache.entries[pos].added = time(NULL);
	else
	{
		arpcache.entries[pos].ip4 = ip4;
		memcpy(arpcache.entries[pos].mac, mac, ETH_ALEN);
		arpcache.entries[pos].added = time(NULL);
		arpcache.entries[pos].valid = 1;
	}

	// if there are pending packets waiting for this mapping,
	// fill the ethernet header for each of them, and send them out
	struct arp_req *req_entry, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &arpcache.req_list, list)
	{
		if (req_entry->ip4 == ip4)
		{
			struct cached_pkt *cached_packet = NULL, *pkt_q;
			list_for_each_entry_safe(cached_packet, pkt_q, &req_entry->cached_packets, list)
			{

				struct ether_header *eth_hdr = (void *)cached_packet->packet;
				memcpy(eth_hdr->ether_dhost, mac, ETH_ALEN);
				iface_send_packet(req_entry->iface, cached_packet->packet, cached_packet->len);
				list_delete_entry(&cached_packet->list);
				free(cached_packet);
			}
			list_delete_entry(&req_entry->list);
			free(req_entry);
		}
	}

	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg)
{
	while (1)
	{
		sleep(1);
		// fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");

		// list to achieve delayed drop (in order to yield critical section)
		struct list_head unreachable_reqs;
		init_list_head(&unreachable_reqs);

		pthread_mutex_lock(&arpcache.lock);

		// For the IP->mac entry, if the entry has been in the table for more than 15 seconds,
		// remove it from the table.
		time_t now = time(NULL);
		for (int i = 0; i < MAX_ARP_SIZE; ++i)
		{
			if (arpcache.entries[i].valid && (int)(now - arpcache.entries[i].added) >= ARP_ENTRY_TIMEOUT)
				arpcache.entries[i].valid = 0;
		}

		// For the pending packets, if the arp request is sent out 1 second ago, while
		// the reply has not been received, retransmit the arp request. If the arp
		// request has been sent 5 times without receiving arp reply, for each
		// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these packets.
		now = time(NULL);
		struct arp_req *req_entry, *req_q;
		list_for_each_entry_safe(req_entry, req_q, &arpcache.req_list, list)
		{
			// retransmit the arp request
			if (req_entry->retries < ARP_REQUEST_MAX_RETRIES)
			{
				if ((int)(now - req_entry->sent) >= 1)
				{
					arp_send_request(req_entry->iface, req_entry->ip4);
					req_entry->sent = now;
					++req_entry->retries;
				}
			}
			// drop req and pending pkts (delayed drop in order to yield critical section)
			else
			{
				list_delete_entry(&req_entry->list);
				list_add_tail(&req_entry->list, &unreachable_reqs);
			}
		}

		pthread_mutex_unlock(&arpcache.lock);

		// delayed drop and send icmp packet
		req_entry = NULL, req_q = NULL;
		list_for_each_entry_safe(req_entry, req_q, &unreachable_reqs, list)
		{
			struct cached_pkt *cached_packet, *pkt_q;
			list_for_each_entry_safe(cached_packet, pkt_q, &req_entry->cached_packets, list)
			{
				icmp_send_packet(cached_packet->packet, cached_packet->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
				list_delete_entry(&cached_packet->list);
				free(cached_packet->packet);
				free(cached_packet);
			}
			list_delete_entry(&req_entry->list);
			free(req_entry);
		}
	}

	return NULL;
}
