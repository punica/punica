/*
 * Punica - LwM2M server with REST API
 * Copyright (C) 2019 8devices
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef CONNECTION_H_
#define CONNECTION_H_

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <liblwm2m.h>
#include "restserver.h"
#include "settings.h"

typedef struct _connection_t
{
    struct _connection_t   *next;
    int                     sock;
    struct sockaddr_in6     addr;
    size_t                  addr_len;
} connection_t;

/*
 * Initialize a UDP connection context
 *
 * Parameters:
 *      api - API context pointer. Is set after return,
 *      port - UDP port to bind to,
 *      address_family - UDP socket family. Can be: AF_INET, AF_INET6 or AF_UNSPEC
 *
 * Returns:
 *      0 on success,
 *      negative value on error
 */
int udp_connection_api_init(connection_api_t **api, int port, int address_family);

int connection_start(void *this);

int connection_close(void *this, void *connection);

int connection_receive(void *this, uint8_t *buffer, size_t size, void **connection,
                       struct timeval *tv);

int connection_send(void *this, void *connection, uint8_t *buffer, size_t length);

int connection_stop(void *this);
#endif
