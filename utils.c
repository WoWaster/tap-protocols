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