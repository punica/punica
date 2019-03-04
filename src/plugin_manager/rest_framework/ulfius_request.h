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

#ifndef ULFIUS_REQUEST_H
#define ULFIUS_REQUEST_H

#include "request.h"

struct CUlfiusRequest;
typedef struct CUlfiusRequest CUlfiusRequest;
CUlfiusRequest *new_UlfiusRequest(const struct _u_request *u_request);
void delete_UlfiusRequest(CUlfiusRequest *c_request);
char *UlfiusRequest_getPath(CUlfiusRequest *c_request);
char *UlfiusRequest_getMethod(CUlfiusRequest *c_request);
char *UlfiusRequest_getHeader(CUlfiusRequest *c_request, const char *c_header);
uint8_t *UlfiusRequest_getBody(CUlfiusRequest *c_request);

#endif // ULFIUS_REQUEST_H
