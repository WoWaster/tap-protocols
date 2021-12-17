#include "parser.h"
#include "globals.h"
#include "protocols/arp/arp.h"
#include "protocols/ipv4/udp/dhcp/dhcp.h"
#include "protocols/ipv4/icmp/icmp.h"
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>

void parse_UDP(char *frame, int fd, struct ether_header *ether_header)
{
	struct udphdr udp_header;
	memcpy(&udp_header, frame + IP_HEADER_OFFSET, sizeof(udp_header));
	if (udp_header.source == htons(68) && udp_header.dest == htons(67))
		parse_DHCP(frame, fd, ether_header);
}

void parse_IP(char *frame, int fd, struct ether_header *ether_header)
{
	struct ip ip_header;
	memcpy(&ip_header, frame + ETHER_HEADER_OFFSET, sizeof(ip_header));
	if (ip_header.ip_p == IPPROTO_UDP)
		parse_UDP(frame, fd, ether_header);
	if (ip_header.ip_p == IPPROTO_ICMP)
		parse_ICMP(frame, fd, ether_header, &ip_header);
}

void parse_frame(char *frame, int fd)
{
	struct ether_header ether_header;
	memcpy(&ether_header, frame, sizeof(ether_header));
	if (ether_header.ether_type == htons(ETHERTYPE_ARP))
		parse_ARP(frame, fd);
	if (ether_header.ether_type == htons(ETHERTYPE_IP))
		parse_IP(frame, fd, &ether_header);
}