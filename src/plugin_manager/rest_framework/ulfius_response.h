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

#ifndef PUNICA_PLUGIN_MANAGER_REST_ULFIUS_RESPONSE_H
#define PUNICA_PLUGIN_MANAGER_REST_ULFIUS_RESPONSE_H

#include <punica/rest/response.h>

struct CUlfiusResponse;
typedef struct CUlfiusResponse CUlfiusResponse;
CUlfiusResponse *new_UlfiusResponse(struct _u_response *u_response);
void delete_UlfiusResponse(CUlfiusResponse *c_response);
void UlfiusResponse_setBody(CUlfiusResponse *c_response, uint8_t *c_binary_data, size_t size);
void UlfiusResponse_setCode(CUlfiusResponse *c_response, const CStatusCode c_code);
void UlfiusResponse_setHeader(CUlfiusResponse *c_response,
                              const char *c_header, const char *c_value);

#endif // PUNICA_PLUGIN_MANAGER_REST_ULFIUS_RESPONSE_H
