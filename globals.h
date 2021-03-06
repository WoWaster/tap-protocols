#ifndef TAP_PROTOCOLS_GLOBALS_H
#define TAP_PROTOCOLS_GLOBALS_H
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdint.h>

#define ETHER_HEADER_OFFSET sizeof(struct ether_header)
#define IP_HEADER_OFFSET sizeof(struct ether_header) + sizeof(struct ip)
#define UDP_HEADER_OFFSET \
	sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr)

#define MAC_SIZE (sizeof(uint8_t) * ETH_ALEN)

#define SUBNET_SIZE 3
extern const struct in_addr IPS[SUBNET_SIZE];
extern const uint8_t MACS[SUBNET_SIZE][ETH_ALEN];
extern const char *DOMAIN_NAMES[SUBNET_SIZE];
extern const struct in_addr TAP_IP;
#endif //TAP_PROTOCOLS_GLOBALS_H
