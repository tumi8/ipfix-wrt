#include "iface.h"
#include "../ipfixlolib/msg.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>

int iface_info(const char *device_name, struct ifreq *req, int *existing_fd) {
	int fd = *existing_fd;

	if (fd < 0) {
		fd = socket(AF_INET, SOCK_DGRAM, 0);

		if (fd == -1) {
			msg(MSG_ERROR, "Failed to open socket (%s).", strerror(errno));
			return -1;
		}
	}

	strncpy(req->ifr_name, device_name, IFNAMSIZ);
	req->ifr_name[IFNAMSIZ - 1] = 0;

	if (ioctl(fd, SIOCGIFINDEX, req)) {
		msg(MSG_ERROR, "Failed to retrieve interface index for interface %s (%s).", device_name, strerror(errno));
		close(fd);
		return -1;
	}

	*existing_fd = fd;

	return req->ifr_ifindex;
}

int iface_hwaddr(const struct ifreq *info, int fd, struct sockaddr *hwaddr) {
	if (ioctl(fd, SIOCGIFHWADDR, info)) {
		msg(MSG_ERROR, "Failed to retrieve hardware adress (%s).", strerror(errno));
		return -1;
	}

	*hwaddr = info->ifr_hwaddr;
	return 0;
}

int iface_mtu(const struct ifreq *info, int fd) {
	if (ioctl(fd, SIOCGIFMTU, info)) {
		msg(MSG_ERROR, "Failed to retrieve interface MTU (%s).", strerror(errno));
		return -1;
	}

	return info->ifr_mtu;
}
