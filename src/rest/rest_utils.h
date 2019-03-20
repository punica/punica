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

#include "../settings.h"

#include <stdlib.h>
#include <stdint.h>

typedef enum
{
    DEVICE_CREDENTIALS_UNDEFINED = 0,
    DEVICE_CREDENTIALS_PSK = 1,
    DEVICE_CREDENTIALS_CERT = 2,
    DEVICE_CREDENTIALS_NONE = 3,
} credentials_mode_t;

typedef struct
{
    char *uuid;
    char *name;
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t *secret_key;
    size_t secret_key_len;
    uint8_t *serial;
    size_t serial_len;
    credentials_mode_t mode;
} database_entry_t;

int coap_to_http_status(int status);

int utils_get_server_key(uint8_t *buffer, size_t *length, const char *cert_file);

int device_new_credentials(database_entry_t *device_entry, void *context);

json_t *json_object_from_string(const char *string, const char *key);

json_t *json_object_from_binary(uint8_t *buffer, const char *key, size_t buffer_length);

char *string_from_json_object(json_t *j_object, const char *key);

uint8_t *binary_from_json_object(json_t *j_object, const char *key, size_t *buffer_length);

#endif // REST_UTILS_H

