#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	// fprintf(stderr, "TODO: malloc and send icmp packet.\n");

	// parse in_pkt
	struct iphdr *in_pkt_iphdr = packet_to_ip_hdr(in_pkt);
	char *in_pkt_ipdata = IP_DATA(in_pkt_iphdr);

	// prepare out_pkt
	char *out_pkt = NULL;
	int out_pkt_len = 0, icmp_len = 0;

	// icmp_len
	switch (type)
	{
	case ICMP_ECHOREPLY:
		// echo reply icmp data = echo request icmp data
		icmp_len = ntohs(in_pkt_iphdr->tot_len) - IP_HDR_SIZE(in_pkt_iphdr);
		break;
	case ICMP_DEST_UNREACH:
		icmp_len = ICMP_HDR_SIZE + IP_HDR_SIZE(in_pkt_iphdr) + ICMP_COPIED_DATA_LEN;
		break;
	case ICMP_TIME_EXCEEDED:
		icmp_len = ICMP_HDR_SIZE + IP_HDR_SIZE(in_pkt_iphdr) + ICMP_COPIED_DATA_LEN;
		break;
	default:
		// no such type
		break;
	}

	// out_pkt_len
	out_pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len;

	// malloc out_pkt
	out_pkt = malloc(out_pkt_len);
	memset(out_pkt, 0x00, out_pkt_len);

	// out_pkt_iphdr
	struct iphdr *out_pkt_iphdr = packet_to_ip_hdr(out_pkt);
	switch (type)
	{
	case ICMP_ECHOREPLY:
		ip_init_hdr(out_pkt_iphdr, ntohl(in_pkt_iphdr->daddr), ntohl(in_pkt_iphdr->saddr), IP_BASE_HDR_SIZE + icmp_len, IPPROTO_ICMP);
		break;
	case ICMP_DEST_UNREACH:
	{
		rt_entry_t *rt_entry = longest_prefix_match(ntohl(in_pkt_iphdr->saddr));
		if (!rt_entry)
		{
			free(out_pkt);
			return;
		}
		ip_init_hdr(out_pkt_iphdr, rt_entry->iface->ip, ntohl(in_pkt_iphdr->saddr), IP_BASE_HDR_SIZE + icmp_len, IPPROTO_ICMP);
	}
	break;
	case ICMP_TIME_EXCEEDED:
	{
		rt_entry_t *rt_entry = longest_prefix_match(ntohl(in_pkt_iphdr->saddr));
		if (!rt_entry)
		{
			free(out_pkt);
			return;
		}
		ip_init_hdr(out_pkt_iphdr, rt_entry->iface->ip, ntohl(in_pkt_iphdr->saddr), IP_BASE_HDR_SIZE + icmp_len, IPPROTO_ICMP);
	}
	break;
	default:
		// no such type
		break;
	}

	// icmp
	char *out_pkt_ipdata = IP_DATA(out_pkt_iphdr);
	struct icmphdr *out_pkt_icmphdr = (void *)out_pkt_ipdata;
	switch (type)
	{
	case ICMP_ECHOREPLY:
		out_pkt_icmphdr->icmp_identifier = 0;
		out_pkt_icmphdr->icmp_sequence = 0;
		struct icmphdr *in_pkt_icmphdr = (void *)in_pkt_ipdata;
		// copy icmp data
		memcpy((char *)out_pkt_icmphdr + ICMP_HDR_SIZE, (char *)in_pkt_icmphdr + ICMP_HDR_SIZE, icmp_len - ICMP_HDR_SIZE);
		break;
	case ICMP_DEST_UNREACH:
		out_pkt_icmphdr->icmp_identifier = 0;
		out_pkt_icmphdr->icmp_sequence = 0;
		memcpy((char *)out_pkt_icmphdr + ICMP_HDR_SIZE, in_pkt_iphdr, icmp_len - ICMP_HDR_SIZE);
		break;
	case ICMP_TIME_EXCEEDED:
		out_pkt_icmphdr->icmp_identifier = 0;
		out_pkt_icmphdr->icmp_sequence = 0;
		memcpy((char *)out_pkt_icmphdr + ICMP_HDR_SIZE, in_pkt_iphdr, icmp_len - ICMP_HDR_SIZE);
		break;
	default:
		// no such type
		break;
	}
	out_pkt_icmphdr->type = type;
	out_pkt_icmphdr->code = code;
	out_pkt_icmphdr->checksum = icmp_checksum(out_pkt_icmphdr, icmp_len);

	// ip_send_packet
	if (out_pkt)
		ip_send_packet(out_pkt, out_pkt_len);
}
