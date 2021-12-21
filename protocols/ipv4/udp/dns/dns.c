#include "dns.h"
#include "../../../../globals.h"
#include "../../../../utils.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DNS_IP_SIZE                                         \
	sizeof(struct ip) + sizeof(struct udphdr) +         \
		sizeof(struct dns_header) + name_length +   \
		sizeof(struct dns_question) + name_length + \
		sizeof(struct dns_record)

void send_answer(int fd, struct ether_header *ether_header,
		 struct ip *ip_header_in, struct udphdr *udp_header,
		 struct dns_header *dns_header, char *name, int name_length,
		 struct dns_question *dns_question)
{
	int index = is_domain_name_in_subnet(name, name_length);
	if (index == -1)
		return;

	struct ether_header ether_header_out;
	fill_ether_header(ether_header, &ether_header_out,
			  ether_header->ether_dhost);

	struct ip ip_header_out;
	memset(&ip_header_out, 0, sizeof(struct ip));
	ip_header_out.ip_v = 4;
	ip_header_out.ip_hl = 5;
	ip_header_out.ip_len = htons(DNS_IP_SIZE);
	ip_header_out.ip_ttl = 255;
	ip_header_out.ip_p = IPPROTO_UDP;
	ip_header_out.ip_src = IPS[0];
	ip_header_out.ip_dst = ip_header_in->ip_src;
	ip_header_out.ip_sum =
		finish_sum(checksum(&ip_header_out, sizeof(ip_header_out), 0));

	struct udphdr udp_header_out;
	udp_header_out.source = udp_header->dest;
	udp_header_out.dest = udp_header->source;
	udp_header_out.len = htons(DNS_IP_SIZE - sizeof(struct ip));
	udp_header_out.check = 0;

	struct dns_header dns_header_out;
	memset(&dns_header_out, 0, sizeof(struct dns_header));
	dns_header_out.id = dns_header->id;
	dns_header_out.qr = 1;
	dns_header_out.qdcout = htons(1);
	dns_header_out.ancount = htons(1);

	struct dns_record dns_record_out;
	dns_record_out.type = htons(1);
	dns_record_out.class = htons(1);
	dns_record_out.ttl = htonl(300);
	dns_record_out.rdlength = htons(4);
	dns_record_out.rdata = IPS[index].s_addr;

	char *buffer = malloc(sizeof(struct ether_header) + DNS_IP_SIZE);

	memcpy(buffer, &ether_header_out, sizeof(struct ether_header));
	size_t delta = sizeof(struct ether_header);
	memcpy(buffer + delta, &ip_header_out, sizeof(struct ip));
	delta += sizeof(struct ip);
	memcpy(buffer + delta, &udp_header_out, sizeof(struct udphdr));
	delta += sizeof(struct udphdr);
	memcpy(buffer + delta, &dns_header_out, sizeof(struct dns_header));
	delta += sizeof(struct dns_header);
	memcpy(buffer + delta, name, name_length);
	delta += name_length;
	memcpy(buffer + delta, dns_question, sizeof(struct dns_question));
	delta += sizeof(struct dns_question);
	memcpy(buffer + delta, name, name_length);
	delta += name_length;
	memcpy(buffer + delta, &dns_record_out, sizeof(struct dns_record));

	ssize_t error =
		write(fd, buffer, sizeof(struct ether_header) + DNS_IP_SIZE);
	if (error == -1) {
		perror("write(DNS)");
		return;
	}
	printf("Sent DNS packet\n");
}

void parse_DNS(char *frame, int fd, struct ether_header *ether_header,
	       struct ip *ip_header_in, struct udphdr *udp_header)
{
	struct dns_header dns_header;
	memcpy(&dns_header, frame + UDP_HEADER_OFFSET,
	       sizeof(struct dns_header));

	uint16_t data_length = ntohs(udp_header->len) - sizeof(struct udphdr) -
			       sizeof(struct dns_header) -
			       sizeof(struct dns_question);

	struct dns_question dns_question;
	memcpy(&dns_question,
	       frame + UDP_HEADER_OFFSET + sizeof(struct dns_header) +
		       data_length,
	       sizeof(struct dns_question));
	if (dns_question.qtype != htons(1))
		return;

	char *data = malloc(data_length * sizeof(char));
	memcpy(data, frame + UDP_HEADER_OFFSET + sizeof(struct dns_header),
	       data_length);

	send_answer(fd, ether_header, ip_header_in, udp_header, &dns_header,
		    data, data_length, &dns_question);

	free(data);
}