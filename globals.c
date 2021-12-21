#include "globals.h"
// 192.168.25.1, 192.168.25.178, 192.168.25.243 in network byte order
const struct in_addr IPS[SUBNET_SIZE] = { { 0x0119a8c0 },
					  { 0xb219a8c0 },
					  { 0xf319a8c0 } };

const uint8_t MACS[SUBNET_SIZE][ETH_ALEN] = {
	{ 0x86, 0xb7, 0xfb, 0x4d, 0x7a, 0x70 },
	{ 0x86, 0xb7, 0xfb, 0x4a, 0xa9, 0xcd },
	{ 0x86, 0xb7, 0xfb, 0x46, 0x5c, 0x24 }
};

const char *DOMAIN_NAMES[SUBNET_SIZE] = { "\6server", "\7client1", "" };

// 192.168.25.42 in network byte order
const struct in_addr TAP_IP = { 0x2a19a8c0 };
