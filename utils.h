#ifndef TAP_PROTOCOLS_UTILS_H
#define TAP_PROTOCOLS_UTILS_H
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>

int is_ip_in_subnet(struct in_addr);

uint32_t checksum(void *buffer, unsigned int count, uint32_t startsum);
uint32_t finish_sum(uint32_t sum);

void fill_ether_header(struct ether_header *ether_header_in,
		       struct ether_header *ether_header_out,
		       const uint8_t source[ETH_ALEN]);
#endif //TAP_PROTOCOLS_UTILS_H
