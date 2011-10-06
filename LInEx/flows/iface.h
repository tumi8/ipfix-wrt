/**
  * Network interface related helper functions
  */
#ifndef IFACE_H_
#define IFACE_H_
#include <sys/socket.h>
#include <net/if.h>

int iface_info(const char *device_name, struct ifreq *info, int *existing_fd);
int iface_hwaddr(const struct ifreq *info, int fd, struct sockaddr *hwaddr);
int iface_mtu(const struct ifreq *info, int fd);

#endif
