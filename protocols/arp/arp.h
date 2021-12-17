#ifndef TAP_PROTOCOLS_ARP_H
#define TAP_PROTOCOLS_ARP_H
#include <net/ethernet.h>
#include <netinet/in.h>

struct arp {
	uint16_t hrd; // Hardware type
	uint16_t pro; // Protocol type
	uint8_t hln; // Hardware address length
	uint8_t pln; // Protocol address length
	uint16_t op; // Opcode
	uint8_t sha[ETH_ALEN]; // Sender hardware address
	struct in_addr spa; // Sender protocol address
	uint8_t tha[ETH_ALEN]; // Target hardware address
	struct in_addr tpa; // Target protocol address
} __attribute__((__packed__));

struct arp_packet {
	struct ether_header ether_header;
	struct arp arp_header;
} __attribute__((__packed__));

void parse_ARP(char *frame, int fd);

#endif //TAP_PROTOCOLS_ARP_H
