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

#ifndef DATABASE_H
#define DATABASE_H

#include <stdlib.h>
#include <stdint.h>

#include "punica.h"

#define DATABASE_UUID_KEY_BIT       0x1
#define DATABASE_PSK_KEY_BIT        0x2
#define DATABASE_PSK_ID_KEY_BIT     0x4
#define DATABASE_ALL_NEW_KEYS_SET   0x6
#define DATABASE_ALL_KEYS_SET       0x7

typedef struct
{
    char *uuid;
    uint8_t *psk;
    size_t psk_len;
    uint8_t *psk_id;
    size_t psk_id_len;
} database_entry_t;

// void database_free_entry(database_entry_t *device_entry);
void devices_database_entry_free(database_entry_t *device);

// int database_validate_new_entry(json_t *j_new_device_object);
int devices_database_new_entry_validate(json_t *j_new_entry);
// int database_validate_entry(json_t *j_device_object);
int devices_database_entry_validate(json_t *j_device);

// int database_populate_entry(
//     database_entry_t *device_entry, json_t *j_device_object);
int devices_database_entry_from_json(json_t *j_device,
                                     database_entry_t *device);

// int database_populate_new_entry(
//     database_entry_t *device_entry, json_t *j_new_device_object);
int devices_database_entry_new_from_json(json_t *j_new_device,
                                         database_entry_t *device);

// int database_prepare_array(json_t *j_array, linked_list_t *device_list);
int devices_database_to_json(linked_list_t *devices, json_t *j_devices);

// int database_load_file(punica_context_t *punica);
int devices_database_from_file(punica_context_t *punica);

#endif //DATABASE_H
