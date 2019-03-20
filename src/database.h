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

#include "punica.h"

int database_load_file(rest_context_t *rest);

int database_validate_entry(json_t *j_device_object);
int database_validate_new_entry(json_t *j_new_device_object);

database_entry_t *database_create_entry(json_t *j_device_object);
database_entry_t *database_create_new_entry(json_t *j_new_device_object, linked_list_t *device_list,
                                            const char *certificate, const char *private_key);
void database_free_entry(database_entry_t *device_entry);

int database_list_to_json_array(linked_list_t *device_list, json_t *j_array);

database_entry_t *database_get_entry_by_uuid(linked_list_t *device_list, const char *uuid);

#endif //DATABASE_H
