#include <fcntl.h>
#include <stdio.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>

int allocate_tap(char *dev)
{
	int tap_fd = open("/dev/net/tun", O_RDWR);
	if (tap_fd == -1) {
		perror("open(tap)");
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	int error = ioctl(tap_fd, TUNSETIFF, &ifr);
	if (error == -1) {
		close(tap_fd);
		perror("ioctl(TUNSETIFF)");
		return -1;
	}

	strcpy(dev, ifr.ifr_name);

	return tap_fd;
}

int main()
{
	char dev[IFNAMSIZ];

	int tap_fd = allocate_tap(dev);
	if (tap_fd == -1)
		return 1;

	close(tap_fd);
	return 0;
}