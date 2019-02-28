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
#include <string.h>
#include <uuid/uuid.h>

#include "rest-utils.h"

#include "punica.h"

#define DATABASE_UUID_KEY_BIT       0x1
#define DATABASE_PSK_KEY_BIT        0x2
#define DATABASE_PSK_ID_KEY_BIT     0x4
#define DATABASE_ALL_NEW_KEYS_SET   0x6
#define DATABASE_ALL_KEYS_SET       0x7

int coap_to_http_status(int status)
{
    switch (status)
    {
    case COAP_204_CHANGED:
    case COAP_205_CONTENT:
        return HTTP_200_OK;

    case COAP_404_NOT_FOUND:
        return HTTP_404_NOT_FOUND;

    default:
        return -(((status >> 5) & 0x7) * 100 + (status & 0x1F));
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
            if (base64_decode(json_string_value(j_value), buffer, &buffer_len))
            {
                return -1;
            }

            key_check |= DATABASE_PSK_KEY_BIT;
        }
        else if (strcasecmp(key, "psk_id") == 0)
        {
            if (base64_decode(json_string_value(j_value), buffer, &buffer_len))
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
            if (base64_decode(json_string_value(j_value), buffer, &buffer_len))
            {
                return -1;
            }
            key_check |= DATABASE_PSK_KEY_BIT;
        }
        else if (strcasecmp(key, "psk_id") == 0)
        {
            if (base64_decode(json_string_value(j_value), buffer, &buffer_len))
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

int database_populate_entry(json_t *j_device_object, database_entry_t *device_entry)
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
    base64_decode(json_string, device_entry->psk_id, &device_entry->psk_id_len);

    return 0;
}

int database_populate_new_entry(json_t *j_new_device_object, database_entry_t *device_entry)
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

    return_code = database_populate_entry(j_device_object, device_entry);

exit:
    free(uuid);
    json_decref(j_device_object);
    return return_code;
}

int database_prepare_array(json_t *j_array, rest_list_t *device_list)
{
    rest_list_entry_t *list_entry;
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

    for (list_entry = device_list->head; list_entry != NULL; list_entry = list_entry->next)
    {
        psk_string_len = sizeof(psk_string);
        psk_id_string_len = sizeof(psk_id_string);

        device_entry = (database_entry_t *)list_entry->data;

        base64_encode(device_entry->psk, device_entry->psk_len, psk_string, &psk_string_len);
        base64_encode(device_entry->psk_id, device_entry->psk_id_len, psk_id_string, &psk_id_string_len);

        j_entry = json_pack("{s:s, s:s, s:s}", "uuid", device_entry->uuid, "psk", psk_string, "psk_id",
                            psk_id_string);
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
