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
    DEVICE_CREDENTIALS_PSK = 1,
    DEVICE_CREDENTIALS_CERT = 2,
    DEVICE_CREDENTIALS_NONE = 3,
} credentials_mode_t;

typedef enum
{
    BASE64_NO_ACTION = 0,
    BASE64_DECODE = 1,
    BASE64_ENCODE = 2,
}database_base64_action;


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

void database_free_entry(database_entry_t *device_entry);

int database_validate_new_entry(json_t *j_new_device_object, linked_list_t *device_list);
int database_validate_entry(json_t *j_device_object, linked_list_t *device_list);

database_entry_t *database_create_entry(json_t *j_device_object);
database_entry_t *database_create_new_entry(json_t *j_new_device_object, void *context);

int database_list_to_json_array(linked_list_t *device_list, json_t *j_array);

json_t *database_entry_to_json(void *entry, const char *key, database_base64_action action, size_t entry_size);
void *database_json_to_entry(json_t *j_object, const char *key, database_base64_action action, size_t *entry_size);

int utils_get_server_key(uint8_t *buffer, size_t *length, const char *cert_file);

database_entry_t *database_get_entry_by_name(linked_list_t *device_list, const char *name);

#endif // REST_UTILS_H

