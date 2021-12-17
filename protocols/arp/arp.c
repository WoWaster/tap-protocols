#include "arp.h"
#include "../../globals.h"
#include "../../utils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void parse_ARP(char *frame, int fd)
{
	struct arp arp_header_in;
	memcpy(&arp_header_in, frame + ETHER_HEADER_OFFSET, sizeof(struct arp));

	if (arp_header_in.op != htons(1)) // Only ARP requests are supported
		return;

	int index = is_ip_in_subnet(arp_header_in.tpa);
	if (index == -1)
		return;

	struct ether_header ether_header_out;
	memcpy(&ether_header_out.ether_dhost, arp_header_in.sha, MAC_SIZE);
	memcpy(&ether_header_out.ether_shost, MACS[index], MAC_SIZE);
	ether_header_out.ether_type = htons(ETHERTYPE_ARP);

	struct arp arp_header_out;
	arp_header_out.hrd = htons(1); // Ethernet
	arp_header_out.pro = htons(ETHERTYPE_IP); // IPv4
	arp_header_out.hln = 6; // MAC length
	arp_header_out.pln = 4; // IPv4 address length
	arp_header_out.op = htons(2); // ARP reply
	memcpy(&arp_header_out.sha, MACS[index], MAC_SIZE);
	arp_header_out.spa = IPS[index];
	memcpy(&arp_header_out.tha, arp_header_in.sha, MAC_SIZE);
	arp_header_out.tpa = arp_header_in.spa;

	struct arp_packet arp_packet = { ether_header_out, arp_header_out };

	ssize_t error = write(fd, &arp_packet, sizeof(arp_packet));
	if (error == -1) {
		perror("write(ARP)");
		return;
	}
	printf("Sent ARP reply\n");
}
