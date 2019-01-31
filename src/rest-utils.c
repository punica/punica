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

#include "rest-utils.h"

#include "restserver.h"

#define DATABASE_UUID_KEY_BIT       0x1
#define DATABASE_PSK_KEY_BIT        0x2
#define DATABASE_PSK_ID_KEY_BIT     0x4
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
