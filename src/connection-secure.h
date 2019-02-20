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
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include "restserver.h"

typedef struct _device_connection_t
{
    struct _device_connection_t *next;
    int sock;
    gnutls_session_t session;
    struct sockaddr_storage addr;
    socklen_t addr_size;
} device_connection_t;

/*
 * Initialize a DTLS connection context
 *
 * Parameters:
 *      api - API context pointer. Is set after return,
 *      port - UDP port to bind to,
 *      address_family - UDP socket family. Can be: AF_INET, AF_INET6 or AF_UNSPEC,
 *      cert_file - path to a ECDHE-ECDSA certificate in file system,
 *      key_file - path to a matching x509 private key file,
 *      data - pointer to a data structure for use in a PSK authentication callback,
 *      psk_cb - pointer to callback used during DTLS handshake with PSK key exchange
 *
 * Returns:
 *      0 on success,
 *      negative value on error
 */
int dtls_connection_api_init(connection_api_t **api, int port, int address_family,
                             const char *cert_file, const char *key_file, void *data, f_psk_cb_t psk_cb);

int connection_start_secure(void *this);

int connection_receive_secure(void *this, uint8_t *buffer, size_t size, void **connection,
                              struct timeval *tv);

int connection_send_secure(void *this, void *connection, uint8_t *buffer, size_t length);

int connection_close_secure(void *this, void *connection);

int connection_stop_secure(void *this);

int connection_validate_secure(char *name, void *connection);

#endif