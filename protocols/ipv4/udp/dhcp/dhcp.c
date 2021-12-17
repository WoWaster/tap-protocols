#include "dhcp.h"
#include "../../../../utils.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define DHCP_IP_SIZE \
	sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct dhcphdr)
#define DHCP_UDP_SIZE sizeof(struct udphdr) + sizeof(struct dhcphdr)

enum { DHCPDISCOVER = 1, DHCPOFFER = 2, DHCPREQEST = 3, DHCPACK = 5 };

uint8_t options[OPTS_LEN] = { DHCP_MESSAGE_TYPE,
			      1,
			      0,
			      SUBNET_MASK,
			      4,
			      255,
			      255,
			      255,
			      0,
			      ROUTER,
			      4,
			      192,
			      168,
			      25,
			      1,
			      DNS_NAME_SERVER,
			      4,
			      192,
			      168,
			      25,
			      1,
			      BROADCAST_ADDRESS,
			      4,
			      192,
			      168,
			      25,
			      255,
			      IP_ADDRESS_LEASE_TIME,
			      4,
			      0x0,
			      0x0,
			      0xa8,
			      0xc0,
			      SERVER_IDENTIFIER,
			      4,
			      192,
			      168,
			      25,
			      1,
			      END };

void reply(int fd, struct ether_header *eth_header, struct dhcphdr *dhcp_header)
{
	struct ether_header eth_header_out;
	memcpy(&eth_header_out.ether_dhost, eth_header->ether_shost, MAC_SIZE);
	memcpy(&eth_header_out.ether_shost, MACS[0], MAC_SIZE);
	eth_header_out.ether_type = htons(ETHERTYPE_IP);

	struct ip ip_header_out;
	memset(&ip_header_out, 0, sizeof(struct ip));
	ip_header_out.ip_v = 4;
	ip_header_out.ip_hl = 5;
	ip_header_out.ip_len = htons(DHCP_IP_SIZE);
	ip_header_out.ip_ttl = 255;
	ip_header_out.ip_p = IPPROTO_UDP;
	ip_header_out.ip_src = IPS[0];
	inet_aton("255.255.255.255", &ip_header_out.ip_dst);
	ip_header_out.ip_sum =
		finish_sum(checksum(&ip_header_out, sizeof(ip_header_out), 0));

	struct udphdr udp_header_out;
	udp_header_out.source = htons(67);
	udp_header_out.dest = htons(68);
	udp_header_out.len = htons(DHCP_UDP_SIZE);
	udp_header_out.check = 0;

	struct dhcphdr dhcp_header_out;
	memset(&dhcp_header_out, 0, sizeof(struct dhcphdr));
	dhcp_header_out.op = 2;
	dhcp_header_out.htype = 1;
	dhcp_header_out.hlen = ETH_ALEN;
	dhcp_header_out.xid = dhcp_header->xid;
	dhcp_header_out.yiaddr = TAP_IP;
	dhcp_header_out.siaddr = IPS[0];
	memcpy(&dhcp_header_out.chaddr, eth_header->ether_shost, MAC_SIZE);
	dhcp_header_out.magic_cookie = MAGIC_COOKIE;
	memcpy(&dhcp_header_out.options, options, sizeof(options));
	switch (dhcp_header->options[2]) {
	case DHCPDISCOVER:
		dhcp_header_out.options[2] = DHCPOFFER;
		break;
	case DHCPREQEST:
		dhcp_header_out.options[2] = DHCPACK;
		break;
	}

	/* Calculate checksum for pseudo header */
	uint32_t udpsum = checksum(&ip_header_out.ip_src,
				   sizeof(ip_header_out.ip_src), 0);
	udpsum = checksum(&ip_header_out.ip_dst, sizeof(ip_header_out.ip_dst),
			  udpsum);
	uint16_t temp = htons(IPPROTO_UDP);
	udpsum = checksum(&temp, sizeof(temp), udpsum);
	temp = udp_header_out.len;
	udpsum = checksum(&temp, sizeof(temp), udpsum);

	/* Add in the checksum for the udp header */
	udpsum = checksum(&udp_header_out, sizeof(udp_header_out), udpsum);

	/* Add in the checksum for the data */
	udpsum = checksum(&dhcp_header_out, sizeof(dhcp_header_out), udpsum);
	udp_header_out.check = finish_sum(udpsum);

	struct dhcppacket dhcppacket = { eth_header_out, ip_header_out,
					 udp_header_out, dhcp_header_out };

	ssize_t error = write(fd, &dhcppacket, sizeof(dhcppacket));
	if (error == -1) {
		perror("write(DHCP)");
		return;
	}
	switch (dhcp_header->options[2]) {
	case DHCPDISCOVER:
		printf("Sent DHCPOFFER\n");
		break;
	case DHCPREQEST:
		printf("Sent DHCPACK\n");
		break;
	}
}

void parse_DHCP(char *frame, int fd, struct ether_header *eth_header)
{
	struct dhcphdr dhcp_header;
	memcpy(&dhcp_header, frame + UDP_HEADER_OFFSET, sizeof(dhcp_header));

	if (dhcp_header.magic_cookie != MAGIC_COOKIE)
		return; // No magic cookie => BOOTP packet, ignore

	int i = 0;
	while (dhcp_header.options[i] != 255) {
		if (dhcp_header.options[i] == DHCP_MESSAGE_TYPE) {
			switch (dhcp_header.options[i + 2]) {
			case DHCPDISCOVER:
				printf("Received DHCPDISCOVER\n");
				break;
			case DHCPREQEST:
				printf("Received DHCPREQUEST\n");
				break;
			}
			reply(fd, eth_header, &dhcp_header);
			break;
		} else {
			i += dhcp_header.options[i + 1] + 2;
		}
	}
}