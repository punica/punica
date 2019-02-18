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

int utils_coap_to_http_status(int status);

size_t utils_get_random(void *buf, size_t buflen);

int utils_generate_async_response_id(char *id);
int utils_generate_uuid(char *uuid);

lwm2m_client_t *utils_find_client(lwm2m_client_t *list, const char *name);

const char *utils_binding_to_string(lwm2m_binding_t bind);

/*
 * Decodes base64 string into binary buffer and calculates its length.
 * base64_string [in] - a null-terminated base64 string.
 * data [out] - pointer to a buffer, can be NULL (in this case function
 *              calculates required buffer length).
 * length [in/out] - length of the data buffer (in)
                     OR length of opaque base64 data (out).
 * Returns 0 on success, negative value on error:
 *      BASE64_ERR_STR_SIZE (-1) supplied base64_string length is too small
 *      BASE64_ERR_INV_CHAR (-2) base64 string contains invalid characters
 *      BASE64_ERR_BUF_SIZE (-3) provided binary buffer length is too small
 *      BASE64_ERR_ARG      (-4) invalid function arguments
 */
int base64_decode(const char *base64_string, uint8_t *data, size_t *length);

/*
 * Encodes binary data into base64 string and calculate its length.
 * data [in] - binary data to be encoded
 * length [in] - length of the binary data
 * base64_string [out] - pointer to a string buffer, can be NULL
 * base64_length [in/out] - pointer to string buffer length (in)
                            OR length of encoded base64 string (out)
                               (NOT INCLUDING THE NULL TERMINATOR).
 * Returns 0 on success, negative value on error:
 *      BASE64_ERR_STR_SIZE (-1) supplied base64_string length is too small
 *      BASE64_ERR_INV_CHAR (-2) base64 string contains invalid characters
 *      BASE64_ERR_BUF_SIZE (-3) provided binary buffer length is too small
 *      BASE64_ERR_ARG      (-4) invalid function arguments
 */
int base64_encode(const uint8_t *data, size_t length,
                  char *base64_string, size_t *base64_length);


#endif // UTILS_H
