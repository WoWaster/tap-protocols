#include "icmp.h"
#include "../../../globals.h"
#include "../../../utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void send_echo_reply(char *frame, int fd, struct ether_header *ether_header,
		     struct ip *ip_header, struct icmphdr *icmp_header)
{
	int index = is_ip_in_subnet(ip_header->ip_dst);
	if (index == -1)
		return;

	size_t data_size = ntohs(ip_header->ip_len) - 20 - 16;
	uint8_t *data = malloc(data_size * sizeof(uint8_t));
	memcpy(data, frame + IP_HEADER_OFFSET + 16,
	       data_size * sizeof(uint8_t));

	uint32_t send_time = (uint32_t)time(NULL);
	uint32_t padding = 0x0;

	struct ether_header ether_header_out;
	fill_ether_header(ether_header, &ether_header_out,
			  ether_header->ether_dhost);

	struct ip ip_header_out;
	memset(&ip_header_out, 0, sizeof(struct ip));
	ip_header_out.ip_v = 4;
	ip_header_out.ip_hl = 5;
	ip_header_out.ip_len = htons(sizeof(struct ip) + ICMP_FULL_SIZE);
	ip_header_out.ip_ttl = 255;
	ip_header_out.ip_p = IPPROTO_ICMP;
	ip_header_out.ip_src = IPS[index];
	ip_header_out.ip_dst = ip_header->ip_src;
	ip_header_out.ip_sum =
		finish_sum(checksum(&ip_header_out, sizeof(ip_header_out), 0));

	struct icmphdr icmp_header_out;
	memset(&icmp_header_out, 0, sizeof(struct icmphdr));
	icmp_header_out.un.echo.id = icmp_header->un.echo.id;
	icmp_header_out.un.echo.sequence = icmp_header->un.echo.sequence;
	icmp_header_out.checksum =
		checksum(&icmp_header_out, sizeof(icmp_header_out), 0);

	icmp_header_out.checksum =
		checksum(&padding, sizeof(padding), icmp_header_out.checksum);

	icmp_header_out.checksum = checksum(&send_time, sizeof(send_time),
					    icmp_header_out.checksum);

	icmp_header_out.checksum = finish_sum(checksum(
		data, data_size * sizeof(uint8_t), icmp_header_out.checksum));

	struct icmp_packet icmp_packet = { ether_header_out, ip_header_out,
					   icmp_header_out, send_time,
					   padding };

	uint8_t *buffer = malloc(sizeof(struct icmp_packet) +
				 data_size * sizeof(uint8_t));
	memcpy(buffer, &icmp_packet, sizeof(icmp_packet));
	memcpy(buffer + sizeof(struct icmp_packet), data,
	       data_size * sizeof(uint8_t));

	ssize_t error =
		write(fd, buffer,
		      sizeof(struct icmp_packet) + data_size * sizeof(uint8_t));
	free(data);
	free(buffer);
	if (error == -1) {
		perror("write(ICMP)");
		return;
	}
	printf("Sent ICMP echo reply\n");
}

void parse_ICMP(char *frame, int fd, struct ether_header *ether_header,
		struct ip *ip_header)
{
	struct icmphdr icmp_header;
	memcpy(&icmp_header, frame + IP_HEADER_OFFSET, sizeof(struct icmphdr));

	switch (icmp_header.type) {
	case 8:
		send_echo_reply(frame, fd, ether_header, ip_header,
				&icmp_header);
		break;
	default:
		printf("ICMP type %d received\n", icmp_header.type);
		break;
	}
}