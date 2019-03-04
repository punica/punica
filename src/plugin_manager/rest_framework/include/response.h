/*
 * MIT License
 *
 * Copyright (c) 2018 8devices
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef RESPONSE_H
#define RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef enum {
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
