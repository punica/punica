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

#ifndef RESPONSE_H
#define RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef enum
{
    StatusCode_unknown = 0,
    StatusCode_information_continue = 100,
    StatusCode_success_ok = 200,
    StatusCode_success_created = 201,
    StatusCode_success_accepted = 202,
    StatusCode_success_no_content = 204,
    StatusCode_success_reset_content = 205,
    StatusCode_client_error = 400,
    StatusCode_client_error_unauthorized = 401,
    StatusCode_client_error_forbidden = 403,
    StatusCode_client_error_not_found = 404,
    StatusCode_client_error_method_not_allowed = 405,
    StatusCode_client_error_not_acceptable = 406,
    StatusCode_server_error_internal_server_error = 500
} CStatusCode;

struct CResponse;
typedef struct CResponse CResponse;

void delete_Response(CResponse *c_response);
void Response_setBody(CResponse *c_response, uint8_t *c_binary_data, size_t size);
void Response_setCode(CResponse *c_response, const CStatusCode c_code);
void Response_setHeader(CResponse *c_response, const char *c_header, const char *c_value);

#ifdef __cplusplus
}
#endif

#endif // RESPONSE_H
