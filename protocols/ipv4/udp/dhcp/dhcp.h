#ifndef TAP_PROTOCOLS_DHCP_H
#define TAP_PROTOCOLS_DHCP_H

#include "../../../../globals.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define OPTS_LEN 60
#define MAGIC_COOKIE 0x63538263

enum {
	SUBNET_MASK = 1,
	ROUTER = 3,
	DNS_NAME_SERVER = 6,
	BROADCAST_ADDRESS = 28,
	IP_ADDRESS_LEASE_TIME = 51,
	SERVER_IDENTIFIER = 54,
	DHCP_MESSAGE_TYPE = 53,
	PARAMETER_REQUEST_LIST = 55,
	END = 255,
};

struct dhcp {
	uint8_t op; // Message op code / message type.
	uint8_t htype; // Hardware address type
	uint8_t hlen; // Hardware address length
	uint8_t hops; // Usually set to 0
	uint32_t xid; // Transaction ID
	uint16_t secs; // Seconds elapsed
	uint16_t flags; // Flags
	struct in_addr ciaddr; // Client IP address
	struct in_addr yiaddr; // 'your' (client) IP address.
	struct in_addr siaddr; // IP address of next server to use in bootstrap
	struct in_addr giaddr; // Relay agent IP address
	uint8_t chaddr[6]; // Client hardware address
	uint8_t chaddr_padding[10]; // Should be zeroed
	char sname[64]; // Server name
	char file[128]; // File name
	uint32_t magic_cookie; // Magic cookie
	uint8_t options[OPTS_LEN];
} __attribute__((__packed__));

struct dhcp_packet {
	struct ether_header ether_header;
	struct ip ip_header;
	struct udphdr udp_header;
	struct dhcp dhcp_header;
} __attribute__((__packed__));

void parse_DHCP(char *frame, int fd, struct ether_header *ether_header);

#endif //TAP_PROTOCOLS_DHCP_H
