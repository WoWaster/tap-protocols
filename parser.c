#include <net/ethernet.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "parser.h"
#include "protocols/arp/arp.h"
#include "globals.h"

void parse_IP(char *frame, int fd, struct ether_header *eth_header)
{
	struct ip ip_header;
	memcpy(&ip_header, frame + ETHER_HEADER_OFFSET, sizeof(ip_header));
	if (ip_header.ip_p == IPPROTO_UDP) {
		//TODO: implement UDP
	}
	if (ip_header.ip_p == IPPROTO_ICMP) {
		// TODO: implement ICMP
	}
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