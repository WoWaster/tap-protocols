#ifndef TAP_PROTOCOLS_ICMP_H
#define TAP_PROTOCOLS_ICMP_H
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define ICMP_FULL_SIZE                                         \
	sizeof(struct icmphdr) + sizeof(uint8_t) * data_size + \
		2 * sizeof(uint32_t)

struct icmp_packet {
	struct ether_header ether_header;
	struct ip ip_header;
	struct icmphdr icmphdr;
	uint32_t send_time;
	uint32_t padding;
} __attribute__((__packed__));

void parse_ICMP(char *frame, int fd, struct ether_header *ether_header,
		struct ip *ip_header);
#endif //TAP_PROTOCOLS_ICMP_H
