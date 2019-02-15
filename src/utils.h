/*
 * Punica - LwM2M server with REST API
 * Copyright (C) 2018 8devices
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

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>

#include <liblwm2m.h>

const char *utils_base64_encode(const uint8_t *data, size_t length);

int utils_coap_to_http_status(int status);

size_t utils_get_random(void *buf, size_t buflen);

lwm2m_client_t *utils_find_client(lwm2m_client_t *list, const char *name);

const char *binding_to_string(lwm2m_binding_t bind);

#endif // UTILS_H
