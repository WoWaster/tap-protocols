#include "utils.h"
#include "globals.h"

int is_ip_in_subnet(struct in_addr ip)
{
	int index = -1;
	for (int i = 0; i < SUBNET_SIZE; ++i) {
		if (IPS[i].s_addr == ip.s_addr) {
			index = i;
			break;
		}
	}
	return index;
}

// taken from https://android.googlesource.com/platform/system/core/+/master/libnetutils/packet.c#62
uint32_t checksum(void *buffer, unsigned int count, uint32_t startsum)
{
	uint16_t *up = (uint16_t *)buffer;
	uint32_t sum = startsum;
	uint32_t upper16;
	while (count > 1) {
		sum += *up++;
		count -= 2;
	}
	if (count > 0)
		sum += (uint16_t) * (uint8_t *)up;

	while ((upper16 = (sum >> 16)) != 0)
		sum = (sum & 0xffff) + upper16;

	return sum;
}

uint32_t finish_sum(uint32_t sum)
{
	return ~sum & 0xffff;
}