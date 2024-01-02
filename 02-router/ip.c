#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "rtable.h"

#include <stdio.h>
#include <stdlib.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	// fprintf(stderr, "TODO: handle ip packet.\n");

	// parse packet
	struct iphdr *ip_hdr = packet_to_ip_hdr(packet);
	u32 daddr = ntohl(ip_hdr->daddr);

	// If the packet is ICMP echo request and the destination IP address is equal to
	// the IP address of the iface, send ICMP echo reply;
	// dst is self
	if (daddr == iface->ip)
	{
		switch (ip_hdr->protocol)
		{
		case IPPROTO_ICMP:
			struct icmphdr *icmp_hdr = (void *)IP_DATA(ip_hdr);
			if (icmp_hdr->type == ICMP_ECHOREQUEST)
				icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
			free(packet);
			break;
		default:
			free(packet);
			break;
		}
		return;
	}

	// dst is not self
	// forward IP datagram
	ip_forward_packet(packet, len);
}
