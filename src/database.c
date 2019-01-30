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

#include "settings.h"
#include "rest-core-types.h"
#include "rest-list.h"
#include "restserver.h"

#define DATABASE_UUID_KEY_BIT       0x1
#define DATABASE_PSK_KEY_BIT        0x2
#define DATABASE_PSK_ID_KEY_BIT     0x4
#define DATABASE_ALL_KEYS_SET       0x7

int database_load_file(rest_context_t *rest)
{
    json_error_t error;
    const char *section;
    size_t index;
    json_t *j_value;
    json_t *j_entry;
    json_t *j_database = NULL;
    int key_check;
    int ret = 1;

    rest_list_t *device_list = rest_list_new();
    if (device_list == 0)
    {
        fprintf(stderr, "%s:%d - failed to allocate device list\r\n",
                __FILE__, __LINE__);
        goto exit;
    }

    rest->devicesList = device_list;
    if (rest->settings->coap.database_file == NULL)
    {
//      internal list created, nothing more to do here
        ret = 0;
        goto exit;
    }

    j_database = json_load_file(rest->settings->coap.database_file, 0, &error);
    if (j_database == NULL)
    {
        fprintf(stdout, "%s:%d - database file not found, must be created with /devices REST API\r\n",
                __FILE__, __LINE__);
        ret = 0;
        goto exit;
    }

    if (!json_is_array(j_database))
    {
        fprintf(stderr, "%s:%d - database file must contain a json array\r\n",
                __FILE__, __LINE__);
        rest_list_delete(device_list);
        goto exit;
    }

    int array_size = json_array_size(j_database);
    if (array_size == 0)
    {
//      empty array, must be populated with /devices REST API
        ret = 0;
        goto exit;
    }

    database_entry_t *curr;
    const char *json_string;
    json_array_foreach(j_database, index, j_entry)
    {
        curr = calloc(1, sizeof(database_entry_t));
        key_check = 0;

        json_object_foreach(j_entry, section, j_value)
        {
            if (!json_is_string(j_value))
            {
                fprintf(stderr, "%s:%d - \'%s\' must be a string\r\n",
                        __FILE__, __LINE__, section);
                goto free_device;
            }
            if (strcasecmp(section, "uuid") == 0)
            {
                json_string = json_string_value(j_value);
                curr->uuid = strdup(json_string);
                if (curr->uuid == NULL)
                {
                    fprintf(stderr, "%s:%d - failed to allocate string\r\n",
                            __FILE__, __LINE__);
                    goto free_device;
                }
                key_check |= DATABASE_UUID_KEY_BIT;
            }
            else if (strcasecmp(section, "psk") == 0)
            {
                if ((ret = base64_decode(json_string_value(j_value), NULL, &curr->psk_len)))
                {
                    fprintf(stderr, "%s:%d base64_decode failed with status %d\r\n",
                            __FILE__, __LINE__, ret);
                    goto free_device;
                }
                curr->psk = (uint8_t *)calloc(1, curr->psk_len);
                if (curr->psk == NULL)
                {
                    fprintf(stderr, "%s:%d - failed to allocate buffer\r\n",
                            __FILE__, __LINE__);
                    goto free_device;
                }
                if ((ret = base64_decode(json_string_value(j_value), curr->psk, &curr->psk_len)))
                {
                    fprintf(stderr, "%s:%d base64_decode failed with status %d\r\n",
                            __FILE__, __LINE__, ret);
                    goto free_device;
                }
                key_check |= DATABASE_PSK_KEY_BIT;
            }
            else if (strcasecmp(section, "psk_id") == 0)
            {
                if ((ret = base64_decode(json_string_value(j_value), NULL, &curr->psk_id_len)))
                {
                    fprintf(stderr, "%s:%d base64_decode failed with status %d\r\n",
                            __FILE__, __LINE__, ret);
                    goto free_device;
                }
                curr->psk_id = (uint8_t *)calloc(1, curr->psk_id_len);
                if (curr->psk_id == NULL)
                {
                    fprintf(stderr, "%s:%d - failed to allocate buffer\r\n",
                            __FILE__, __LINE__);
                    goto free_device;
                }
                if ((ret = base64_decode(json_string_value(j_value), curr->psk_id, &curr->psk_id_len)))
                {
                    fprintf(stderr, "%s:%d base64_decode failed with status %d\r\n",
                            __FILE__, __LINE__, ret);
                    goto free_device;
                }
                key_check |= DATABASE_PSK_ID_KEY_BIT;
            }
            else
            {
                fprintf(stdout, "Unrecognised database file key: %s\n", section);
            }
        }

        if (key_check != DATABASE_ALL_KEYS_SET)
        {
            fprintf(stderr, "%s:%d - missing \'key:value\' pair\r\n",
                    __FILE__, __LINE__);
            goto free_device;
        }

        rest_list_add(device_list, (void *)curr);
        continue;

free_device:
        free_database_entry(curr);
    }
    ret = 0;

exit:
    json_decref(j_database);
    return ret;
}
