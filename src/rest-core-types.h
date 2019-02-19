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

#ifndef REST_CORE_TYPES_H
#define REST_CORE_TYPES_H

#include <stdint.h>
#include <stdlib.h>

#include "linked_list.h"


enum base64_error_t
{
    BASE64_ERR_NONE     = 0,
    BASE64_ERR_STR_SIZE = -1,
    BASE64_ERR_INV_CHAR = -2,
    BASE64_ERR_BUF_SIZE = -3,
    BASE64_ERR_ARG      = -4,
};

typedef struct
{
    rest_list_t list;
    time_t timestamp;
    char id[40];
    int status;
    const char *payload;
} rest_notif_async_response_t;

typedef rest_notif_async_response_t rest_async_response_t;

typedef struct
{
    rest_list_t list;
    const char *name;
} rest_notif_registration_t;

typedef struct
{
    rest_list_t list;
    const char *name;
} rest_notif_update_t;

typedef struct
{
    rest_list_t list;
    const char *name;
} rest_notif_deregistration_t;

typedef struct
{
    rest_list_t list;
    const char *name;
} rest_notif_timeout_t;

size_t rest_get_random(void *buf, size_t buflen);

rest_async_response_t *rest_async_response_new(void);

rest_async_response_t *rest_async_response_clone(const rest_async_response_t *resp);

void rest_async_response_delete(rest_async_response_t *response);

int rest_async_response_set(rest_async_response_t *resp, int status,
                            const uint8_t *payload, size_t length);


rest_notif_registration_t *rest_notif_registration_new(void);

void rest_notif_registration_delete(rest_notif_registration_t *registration);

int rest_notif_registration_set(rest_notif_registration_t *registration, const char *name);


rest_notif_update_t *rest_notif_update_new(void);

void rest_notif_update_delete(rest_notif_update_t *update);

int rest_notif_update_set(rest_notif_update_t *update, const char *name);


rest_notif_deregistration_t *rest_notif_deregistration_new(void);

void rest_notif_deregistration_delete(rest_notif_deregistration_t *deregistration);

int rest_notif_deregistration_set(rest_notif_deregistration_t *deregistration, const char *name);

/*
 * Decodes base64 string into binary buffer and calculates its length.
 * base64_string [in] - a null-terminated base64 string.
 * data [out] - pointer to a buffer, can be NULL (in this case function calculates required buffer length).
 * length [in/out] - the length of the data buffer (in) / the length of binary base64 data (out).
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
 * base64_length [in/out] - pointer to variable storing length of the string buffer (in) / the length of encoded base64 string (out) (NOT INCLUDING THE NULL TERMINATOR).
 * Returns 0 on success, negative value on error:
 *      BASE64_ERR_STR_SIZE (-1) supplied base64_string length is too small
 *      BASE64_ERR_INV_CHAR (-2) base64 string contains invalid characters
 *      BASE64_ERR_BUF_SIZE (-3) provided binary buffer length is too small
 *      BASE64_ERR_ARG      (-4) invalid function arguments
 */
int base64_encode(const uint8_t *data, size_t length, char *base64_string, size_t *base64_length);

#endif // REST_CORE_TYPES_H

