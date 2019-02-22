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

#include "restserver.h"

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
connection_api_t *udp_connection_api_init(int port, int address_family);

/*
 * Deinitialize a UDP connection context
 *
 * Parameters:
 *      context - API context pointer
 */
void udp_connection_api_deinit(void *context);

#endif
