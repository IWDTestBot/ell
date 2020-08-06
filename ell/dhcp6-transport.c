/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stddef.h>
#include <linux/types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>

#include "ell/io.h"
#include "ell/util.h"
#include "ell/private.h"
#include "ell/dhcp6-private.h"

struct dhcp6_default_transport {
	struct dhcp6_transport super;
	struct l_io *io;
	int udp_fd;
	uint16_t port;
};

static bool _dhcp6_default_transport_read_handler(struct l_io *io,
							void *userdata)
{
	struct dhcp6_default_transport *transport = userdata;
	int fd = l_io_get_fd(io);
	char buf[2048];
	ssize_t len;

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return false;

	if (transport->super.rx_cb)
		transport->super.rx_cb(&buf, len, transport->super.rx_data);

	return true;
}

static int _dhcp6_default_transport_send(struct dhcp6_transport *s,
						const struct in6_addr *dest,
						const void *data, size_t len)
{
	struct dhcp6_default_transport *transport =
		l_container_of(s, struct dhcp6_default_transport, super);
	struct sockaddr_in6 addr;
	int err;

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = L_CPU_TO_BE16(DHCP6_PORT_SERVER);
	memcpy(&addr.sin6_addr, dest, sizeof(addr.sin6_addr));

	err = sendto(l_io_get_fd(transport->io), data, len, 0,
				(struct sockaddr *) &addr, sizeof(addr));

	if (err < 0)
		return -errno;

	return 0;
}

static int kernel_raw_socket_open(uint32_t ifindex, uint16_t port)
{
	static int yes = 1;
	static int no = 0;
	int s;
	struct sockaddr_in6 addr;

	s = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
								IPPROTO_UDP);
	if (s < 0)
		return -errno;

	if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) < 0)
		goto error;

	if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
							&no, sizeof(no)) < 0)
		goto error;

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
		goto error;

	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = L_CPU_TO_BE16(port);
	addr.sin6_scope_id = ifindex;

	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		goto error;

	return s;

error:
	L_TFR(close(s));
	return -errno;
}

static int _dhcp6_default_transport_open(struct dhcp6_transport *s)
{
	struct dhcp6_default_transport *transport =
		l_container_of(s, struct dhcp6_default_transport, super);
	int fd;

	if (transport->io)
		return -EALREADY;

	fd = kernel_raw_socket_open(s->ifindex, transport->port);
	if (fd < 0)
		return fd;

	transport->io = l_io_new(fd);
	l_io_set_close_on_destroy(transport->io, true);
	l_io_set_read_handler(transport->io,
					_dhcp6_default_transport_read_handler,
					transport, NULL);

	return 0;
}

static void _dhcp6_default_transport_close(struct dhcp6_transport *s)
{
	struct dhcp6_default_transport *transport =
		l_container_of(s, struct dhcp6_default_transport, super);

	l_io_destroy(transport->io);
	transport->io = NULL;

	if (transport->udp_fd >= 0) {
		L_TFR(close(transport->udp_fd));
		transport->udp_fd = -1;
	}
}

void _dhcp6_transport_set_rx_callback(struct dhcp6_transport *transport,
					dhcp6_transport_rx_cb_t rx_cb,
					void *userdata)
{
	if (!transport)
		return;

	transport->rx_cb = rx_cb;
	transport->rx_data = userdata;
}

struct dhcp6_transport *_dhcp6_default_transport_new(uint32_t ifindex,
								uint16_t port)
{
	struct dhcp6_default_transport *transport;

	transport = l_new(struct dhcp6_default_transport, 1);

	transport->super.open = _dhcp6_default_transport_open;
	transport->super.close = _dhcp6_default_transport_close;
	transport->super.send = _dhcp6_default_transport_send;

	transport->super.ifindex = ifindex;
	transport->port = port;

	return &transport->super;
}

void _dhcp6_transport_free(struct dhcp6_transport *transport)
{
	if (!transport)
		return;

	if (transport->close)
		transport->close(transport);

	l_free(transport);
}