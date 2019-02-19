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

#ifndef CONNECTION_SECURE_H_
#define CONNECTION_SECURE_H_

#include <arpa/inet.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <liblwm2m.h>
#include "restserver.h"
#include "settings.h"

typedef struct _device_connection_t
{
    struct _device_connection_t *next;
    int sock;
    gnutls_session_t session;
    struct sockaddr_storage addr;
    socklen_t addr_size;
} device_connection_t;

int psk_callback(gnutls_session_t session, const char *username, gnutls_datum_t *key);

void set_psk_callback_data(void *context);

int dtls_connection_api_init(connection_api_t **conn_api, int port, int address_family,
                             const char *cert_file, const char *key_file, void *data);

int connection_start_secure(void *this);

int connection_receive_secure(void *this, uint8_t *buffer, size_t size, void **connection,
                              struct timeval *tv);

int connection_send_secure(void *this, void *connection, uint8_t *buffer, size_t length);

int connection_close_secure(void *this, void *connection);

int connection_stop_secure(void *this);

#endif
