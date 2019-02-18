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

#include "database.h"
#include "linked_list.h"
#include "punica.h"
#include "rest_core_types.h"
#include "settings.h"

#include <uuid/uuid.h>

void free_database_entry(database_entry_t *device)
{

    if (device)
    {
        if (device->uuid)
        {
            free(device->uuid);
        }
        if (device->psk)
        {
            free(device->psk);
        }
        if (device->psk_id)
        {
            free(device->psk_id);
        }

        free(device);
    }
}

void database_free_entry(database_entry_t *device_entry)
{

    if (device_entry)
    {
        if (device_entry->uuid)
        {
            free(device_entry->uuid);
        }
        if (device_entry->psk)
        {
            free(device_entry->psk);
        }
        if (device_entry->psk_id)
        {
            free(device_entry->psk_id);
        }

        free(device_entry);
    }
}

int database_validate_new_entry(json_t *j_new_device_object)
{
    int key_check = 0;
    const char *key;
    json_t *j_value;
    uint8_t buffer[512];
    size_t buffer_len = sizeof(buffer);

    if (!json_is_object(j_new_device_object))
    {
        return -1;
    }

    json_object_foreach(j_new_device_object, key, j_value)
    {
        if (!json_is_string(j_value))
        {
            return -1;
        }

        if (strcasecmp(key, "psk") == 0)
        {
            if (base64_decode(json_string_value(j_value),
                              buffer, &buffer_len))
            {
                return -1;
            }

            key_check |= DATABASE_PSK_KEY_BIT;
        }
        else if (strcasecmp(key, "psk_id") == 0)
        {
            if (base64_decode(json_string_value(j_value),
                              buffer, &buffer_len))
            {
                return -1;
            }

            key_check |= DATABASE_PSK_ID_KEY_BIT;
        }
    }

    if (key_check != DATABASE_ALL_NEW_KEYS_SET)
    {
        return -1;
    }

    return 0;
}

int database_validate_entry(json_t *j_device_object)
{
    int key_check = 0;
    const char *key;
    json_t *j_value;
    uint8_t buffer[512];
    size_t buffer_len = sizeof(buffer);

    if (!json_is_object(j_device_object))
    {
        return -1;
    }

    json_object_foreach(j_device_object, key, j_value)
    {
        if (!json_is_string(j_value))
        {
            return -1;
        }
        if (strcasecmp(key, "uuid") == 0)
        {
            key_check |= DATABASE_UUID_KEY_BIT;
        }
        else if (strcasecmp(key, "psk") == 0)
        {
            if (base64_decode(json_string_value(j_value),
                              buffer, &buffer_len))
            {
                return -1;
            }
            key_check |= DATABASE_PSK_KEY_BIT;
        }
        else if (strcasecmp(key, "psk_id") == 0)
        {
            if (base64_decode(json_string_value(j_value),
                              buffer, &buffer_len))
            {
                return -1;
            }
            key_check |= DATABASE_PSK_ID_KEY_BIT;
        }
    }

//  function does not check for duplicate keys
    if (key_check != DATABASE_ALL_KEYS_SET)
    {
        return -1;
    }

    return 0;
}

int database_populate_entry(database_entry_t *device_entry,
                            json_t *j_device_object)
{
    json_t *j_value;
    const char *json_string;

    if (j_device_object == NULL || device_entry == NULL)
    {
        return -1;
    }

    j_value = json_object_get(j_device_object, "uuid");
    json_string = json_string_value(j_value);

    device_entry->uuid = strdup(json_string);
    if (device_entry->uuid == NULL)
    {
        return -1;
    }


    j_value = json_object_get(j_device_object, "psk");
    json_string = json_string_value(j_value);

    base64_decode(json_string, NULL, &device_entry->psk_len);

    device_entry->psk = (uint8_t *)malloc(device_entry->psk_len);
    if (device_entry->psk == NULL)
    {
        return -1;
    }
    base64_decode(json_string, device_entry->psk, &device_entry->psk_len);


    j_value = json_object_get(j_device_object, "psk_id");
    json_string = json_string_value(j_value);

    base64_decode(json_string, NULL, &device_entry->psk_id_len);

    device_entry->psk_id = (uint8_t *)malloc(device_entry->psk_id_len);
    if (device_entry->psk_id == NULL)
    {
        return -1;
    }
    base64_decode(json_string,
                  device_entry->psk_id, &device_entry->psk_id_len);

    return 0;
}

int database_populate_new_entry(database_entry_t *device_entry,
                                json_t *j_new_device_object)
{
    uuid_t b_uuid;
    char *uuid = NULL;
    int return_code;
    json_t *j_device_object = json_deep_copy(j_new_device_object);

    if (j_device_object == NULL || device_entry == NULL)
    {
        return -1;
    }

    uuid_generate_random(b_uuid);

    uuid = malloc(37);
    if (uuid == NULL)
    {
        return -1;
    }

    uuid_unparse(b_uuid, uuid);

    if (json_object_set_new(
            j_device_object, "uuid", json_stringn(uuid, 37)) != 0)
    {
        return_code = -1;
        goto exit;
    }

    return_code = database_populate_entry(device_entry, j_device_object);

exit:
    free(uuid);
    json_decref(j_device_object);
    return return_code;
}

int database_prepare_array(json_t *j_array, linked_list_t *device_list)
{
    linked_list_entry_t *list_entry;
    database_entry_t *device_entry;
    json_t *j_entry;
    char psk_string[256];
    char psk_id_string[256];
    size_t psk_string_len;
    size_t psk_id_string_len;

    if (device_list == NULL || !json_is_array(j_array))
    {
        return -1;
    }

    for (list_entry = device_list->head;
         list_entry != NULL; list_entry = list_entry->next)
    {
        psk_string_len = sizeof(psk_string);
        psk_id_string_len = sizeof(psk_id_string);

        device_entry = (database_entry_t *)list_entry->data;

        base64_encode(device_entry->psk, device_entry->psk_len,
                      psk_string, &psk_string_len);
        base64_encode(device_entry->psk_id, device_entry->psk_id_len,
                      psk_id_string, &psk_id_string_len);

        j_entry = json_pack("{s:s, s:s, s:s}",
                            "uuid", device_entry->uuid,
                            "psk", psk_string,
                            "psk_id", psk_id_string);

        if (j_entry == NULL)
        {
            return -1;
        }

        if (json_array_append_new(j_array, j_entry))
        {
            return -1;
        }
    }

    return 0;
}

int database_load_file(punica_context_t *punica)
{
    json_error_t error;
    size_t index;
    json_t *j_entry;
    json_t *j_database = NULL;
    int ret = 1;
    database_entry_t *curr;

    linked_list_t *device_list = linked_list_new();
    if (device_list == 0)
    {
        fprintf(stderr, "%s:%d - failed to allocate device list\r\n",
                __FILE__, __LINE__);
        goto exit;
    }

    punica->rest_devices = device_list;
    if (punica->settings->coap.database_file == NULL)
    {
        // internal list created, nothing more to do here
        ret = 0;
        goto exit;
    }

    j_database = json_load_file(
                     punica->settings->coap.database_file, 0, &error);
    if (j_database == NULL)
    {
        fprintf(stdout, "%s:%d - database file not found,",
                __FILE__, __LINE__);
        fprintf(stdout, " must be created with /devices REST API\r\n");
        ret = 0;
        goto exit;
    }

    if (!json_is_array(j_database))
    {
        fprintf(stderr,
                "%s:%d - database file must contain a json array\r\n",
                __FILE__, __LINE__);
        linked_list_delete(device_list);
        goto exit;
    }

    int array_size = json_array_size(j_database);
    if (array_size == 0)
    {
        /* empty array, must be populated with /devices REST API */
        ret = 0;
        goto exit;
    }

    json_array_foreach(j_database, index, j_entry)
    {
        if (database_validate_entry(j_entry))
        {
            fprintf(stdout,
                    "Found error(s) in device entry no. %ld\n",
                    index);
            continue;
        }

        curr = calloc(1, sizeof(database_entry_t));
        if (curr == NULL)
        {
            goto exit;
        }

        if (database_populate_entry(curr, j_entry))
        {
            fprintf(stdout,
                    "Internal server error while managing device entry\n");
            goto free_device;
        }

        linked_list_add(device_list, (void *)curr);
        continue;

free_device:
        database_free_entry(curr);
    }
    ret = 0;

exit:
    json_decref(j_database);
    return ret;
}
