#ifndef TAP_PROTOCOLS_GLOBALS_H
#define TAP_PROTOCOLS_GLOBALS_H
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdint.h>

#define SUBNET_SIZE 3
extern const struct in_addr IPS[SUBNET_SIZE];
extern const uint8_t MACS[SUBNET_SIZE][ETH_ALEN];
extern const struct in_addr TAP_IP;
#endif //TAP_PROTOCOLS_GLOBALS_H
