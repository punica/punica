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

#ifndef REST_UTILS_H
#define REST_UTILS_H

#include <stdint.h>
#include <stdio.h>

const char *base64_encode(const uint8_t *data, size_t length);

int coap_to_http_status(int status);

size_t rest_get_random(void *buf, size_t buflen);

#endif // REST_UTILS_H

