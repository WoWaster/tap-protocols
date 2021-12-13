#ifndef TAP_PROTOCOLS_UTILS_H
#define TAP_PROTOCOLS_UTILS_H
#include <netinet/in.h>
#include <netinet/ip.h>

int is_ip_in_subnet(struct in_addr);

uint32_t checksum(void *buffer, unsigned int count, uint32_t startsum);
uint32_t finish_sum(uint32_t sum);

#endif //TAP_PROTOCOLS_UTILS_H
