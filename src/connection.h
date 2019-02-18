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

#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <liblwm2m.h>

#include "settings.h"

typedef struct _connection_t
{
    struct _connection_t   *next;
    int                     sock;
    struct sockaddr_in6     addr;
    size_t                  addrLen;
} connection_t;

int connection_create(settings_t *options, int addressFamily, void *context);

int connection_free(void *connP);

int connection_step(void *ctx, struct timeval *tv);

int connection_send(void *sessionH, uint8_t *buffer, size_t length);
#endif
