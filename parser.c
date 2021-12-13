#include <net/ethernet.h>
#include <string.h>
#include <netinet/in.h>
#include "parser.h"
#include "protocols/arp/arp.h"

void parse_frame(char *frame, int fd)
{
	struct ether_header ether_header;
	memcpy(&ether_header, frame, sizeof(ether_header));
	if (ether_header.ether_type == htons(ETHERTYPE_ARP))
		parse_ARP(frame, fd);
	if (ether_header.ether_type == htons(ETHERTYPE_IP)) {
		//TODO: implement IP
	}
}