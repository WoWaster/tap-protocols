#ifndef TAP_PROTOCOLS_DNS_H
#define TAP_PROTOCOLS_DNS_H
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

struct dns_header {
	uint16_t id; // Identifier

	uint8_t rd : 1; // Recursion desired
	uint8_t tc : 1; // Truncation flag
	uint8_t aa : 1; // Authoritative Answer flag
	uint8_t opcode : 4; // Operation code
	uint8_t qr : 1; // Query/Response flag

	uint8_t rcode : 4; // Response code
	uint8_t z : 3; // 3 bits set 0
	uint8_t ra : 1; // Recursion available

	uint16_t qdcout; // Question count
	uint16_t ancount; // Answer record count
	uint16_t nscount; // Authority record count
	uint16_t arcount; // Additional record count
} __attribute__((__packed__));

struct dns_question {
	uint16_t qtype; // Question type
	uint16_t qclass; // Question class
} __attribute__((__packed__));

struct dns_record {
	uint16_t type; // Type of RR
	uint16_t class; // Class of RR
	uint32_t ttl; // Max time in cache
	uint16_t rdlength; // Resource data length
	uint32_t rdata; // Resource data // In this case IP address
} __attribute__((__packed__));

void parse_DNS(char *frame, int fd, struct ether_header *ether_header,
	       struct ip *ip_header_in, struct udphdr *udp_header);
#endif //TAP_PROTOCOLS_DNS_H
