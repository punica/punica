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
#include <uuid/uuid.h>
#include "settings.h"
#include "linked_list.h"
#include "punica.h"
#include "utils/base64.h"

#define DATABASE_UUID_KEY_BIT       0x01
#define DATABASE_MODE_KEY_BIT       0x02
#define DATABASE_NAME_KEY_BIT       0x04
#define DATABASE_PUBLIC_KEY_BIT     0x08
#define DATABASE_SECRET_KEY_BIT     0x10
#define DATABASE_SERIAL_KEY_BIT     0x20
#define DATABASE_ALL_NEW_KEYS_SET   0x06
#define DATABASE_ALL_KEYS_SET       0x3F

#define DATABASE_CREDENTIALS_MAX_SIZE 1024

static credentials_mode_t credentials_type_from_string(const char *string)
{
    if (strcasecmp(string, "psk") == 0)
    {
        return DEVICE_CREDENTIALS_PSK;
    }
    else if (strcasecmp(string, "cert") == 0)
    {
        return DEVICE_CREDENTIALS_CERT;
    }
    else if (strcasecmp(string, "none") == 0)
    {
        return DEVICE_CREDENTIALS_NONE;
    }
    else
    {
        return DEVICE_CREDENTIALS_UNDEFINED;
    }
}

static credentials_mode_t credentials_type_from_json(json_t *j_object)
{
    const char *mode;
    json_t *j_value;

    j_value = json_object_get(j_object, "mode");
    if (j_value == NULL)
    {
        return DEVICE_CREDENTIALS_UNDEFINED;
    }

    mode = json_string_value(j_value);
    if (mode == NULL)
    {
        return DEVICE_CREDENTIALS_UNDEFINED;
    }

    return credentials_type_from_string(mode);
}

int database_load_file(rest_context_t *rest)
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
        linked_list_delete(device_list);
        goto exit;
    }

    int array_size = json_array_size(j_database);
    if (array_size == 0)
    {
//      empty array, must be populated with /devices REST API
        ret = 0;
        goto exit;
    }

    json_array_foreach(j_database, index, j_entry)
    {
        if (database_validate_entry(j_entry))
        {
            fprintf(stdout, "Found error(s) in device entry no. %ld\n", index);
            continue;
        }

        curr = database_create_entry(j_entry);
        if (curr == NULL)
        {
            fprintf(stdout, "Internal server error while managing device entry\n");
            continue;
        }

        linked_list_add(device_list, (void *)curr);
    }
    ret = 0;

exit:
    json_decref(j_database);
    return ret;
}

int devices_database_unload(linked_list_t *devices_database)
{
    linked_list_entry_t *list_entry;

    if (devices_database == NULL)
    {
        return 0;
    }

    for (list_entry = devices_database->head;
         list_entry != NULL; list_entry = list_entry->next)
    {
        database_free_entry(list_entry->data);
    }

    linked_list_delete(devices_database);
    return 0;
}

database_entry_t *database_get_entry_by_uuid(linked_list_t *device_list, const char *uuid)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;

    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(uuid, device_data->uuid) == 0)
        {
            return device_data;
        }
    }

    return NULL;
}

void database_free_entry(database_entry_t *device_entry)
{
    if (device_entry)
    {
        if (device_entry->uuid)
        {
            free(device_entry->uuid);
        }
        if (device_entry->name)
        {
            free(device_entry->name);
        }
        if (device_entry->public_key)
        {
            free(device_entry->public_key);
        }
        if (device_entry->secret_key)
        {
            free(device_entry->secret_key);
        }
        if (device_entry->serial)
        {
            free(device_entry->serial);
        }

        free(device_entry);
    }
}

int database_validate_new_entry(json_t *j_new_device_object)
{
    int key_check = 0;
    const char *key, *value_string;
    json_t *j_value;

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

        if (strcasecmp(key, "mode") == 0)
        {
            value_string = json_string_value(j_value);

            if (credentials_type_from_string(value_string) == DEVICE_CREDENTIALS_UNDEFINED)
            {
                return -1;
            }

            key_check |= DATABASE_MODE_KEY_BIT;
        }
        else if (strcasecmp(key, "name") == 0)
        {
            value_string = json_string_value(j_value);

            key_check |= DATABASE_NAME_KEY_BIT;
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
    const char *key, *value_string;
    json_t *j_value;
    uint8_t buffer[DATABASE_CREDENTIALS_MAX_SIZE];
    size_t buffer_len = sizeof(buffer);
    int ret;

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
        else if (strcasecmp(key, "name") == 0)
        {
            value_string = json_string_value(j_value);

            key_check |= DATABASE_NAME_KEY_BIT;
        }
        else if (strcasecmp(key, "mode") == 0)
        {
            value_string = json_string_value(j_value);

            if (credentials_type_from_string(value_string) == DEVICE_CREDENTIALS_UNDEFINED)
            {
                return -1;
            }

            key_check |= DATABASE_MODE_KEY_BIT;
        }
        else if (strcasecmp(key, "public_key") == 0)
        {
            ret = base64_decode(json_string_value(j_value), buffer, &buffer_len);
            if (ret != 0)
            {
                return -1;
            }
            key_check |= DATABASE_PUBLIC_KEY_BIT;
        }
        else if (strcasecmp(key, "secret_key") == 0)
        {
            ret = base64_decode(json_string_value(j_value), buffer, &buffer_len);
            if (ret != 0)
            {
                return -1;
            }
            key_check |= DATABASE_SECRET_KEY_BIT;
        }
        else if (strcasecmp(key, "serial") == 0)
        {
            ret = base64_decode(json_string_value(j_value), buffer, &buffer_len);
            if (ret != 0)
            {
                return -1;
            }
            key_check |= DATABASE_SERIAL_KEY_BIT;
        }
    }

//  function does not check for duplicate keys
    if (key_check != DATABASE_ALL_KEYS_SET)
    {
        return -1;
    }

    return 0;
}

database_entry_t *database_create_entry(json_t *j_device_object)
{
    int status = -1;
    database_entry_t *device_entry = NULL;

    if (j_device_object == NULL)
    {
        return NULL;
    }

    device_entry = calloc(1, sizeof(database_entry_t));
    if (device_entry == NULL)
    {
        return NULL;
    }

    device_entry->mode = credentials_type_from_json(j_device_object);
    if (device_entry->mode == DEVICE_CREDENTIALS_UNDEFINED)
    {
        goto exit;
    }

    device_entry->uuid = string_from_json_object(j_device_object, "uuid");
    device_entry->name = string_from_json_object(j_device_object, "name");

    if (device_entry->uuid == NULL
        || device_entry->name == NULL)
    {
        goto exit;
    }

    switch (device_entry->mode)
    {
    case DEVICE_CREDENTIALS_PSK:
        device_entry->public_key = binary_from_json_object(j_device_object, "public_key",
                                                           &device_entry->public_key_len);
        device_entry->secret_key = binary_from_json_object(j_device_object, "secret_key",
                                                           &device_entry->secret_key_len);

        if (device_entry->public_key == NULL
            || device_entry->secret_key == NULL)
        {
            goto exit;
        }

        break;
    case DEVICE_CREDENTIALS_CERT:
        device_entry->public_key = binary_from_json_object(j_device_object, "public_key",
                                                           &device_entry->public_key_len);
        device_entry->serial = binary_from_json_object(j_device_object, "serial",
                                                       &device_entry->serial_len);

        if (device_entry->public_key == NULL
            || device_entry->serial == NULL)
        {
            goto exit;
        }

        break;
    case DEVICE_CREDENTIALS_NONE:
        break;
    default:
        goto exit;
    }

    status = 0;
exit:
    if (status != 0)
    {
        database_free_entry(device_entry);
        device_entry = NULL;
    }
    return device_entry;
}

database_entry_t *database_create_new_entry(json_t *j_device_object, linked_list_t *device_list,
                                            const char *certificate, const char *private_key)
{
    uuid_t b_uuid;
    char uuid[64];
    int status = -1;
    database_entry_t *device_entry = NULL;

    if (j_device_object == NULL)
    {
        return NULL;
    }

    device_entry = calloc(1, sizeof(database_entry_t));
    if (device_entry == NULL)
    {
        return NULL;
    }

    device_entry->mode = credentials_type_from_json(j_device_object);
    if (device_entry->mode == DEVICE_CREDENTIALS_UNDEFINED)
    {
        goto exit;
    }

    device_entry->name = string_from_json_object(j_device_object, "name");
    if (device_entry->name == NULL)
    {
        goto exit;
    }

    uuid_generate_random(b_uuid);

    uuid_unparse(b_uuid, uuid);
    device_entry->uuid = strdup(uuid);

    if (device_entry->uuid == NULL)
    {
        goto exit;
    }

    if (device_new_credentials(device_entry, device_list, certificate, private_key))
    {
        goto exit;
    }

    status = 0;
exit:
    if (status != 0)
    {
        database_free_entry(device_entry);
        device_entry = NULL;
    }
    return device_entry;
}

int database_list_to_json_array(linked_list_t *device_list, json_t *j_array)
{
    linked_list_entry_t *list_entry;
    database_entry_t *device_entry;
    json_t *j_entry;
    char base64_secret_key[DATABASE_CREDENTIALS_MAX_SIZE];
    char base64_public_key[DATABASE_CREDENTIALS_MAX_SIZE];
    char base64_serial[DATABASE_CREDENTIALS_MAX_SIZE];
    size_t base64_length;
    const char *mode_string;

    if (device_list == NULL || !json_is_array(j_array))
    {
        return -1;
    }

    for (list_entry = device_list->head; list_entry != NULL; list_entry = list_entry->next)
    {
        device_entry = (database_entry_t *)list_entry->data;

        memset(base64_secret_key, 0, sizeof(base64_secret_key));
        memset(base64_public_key, 0, sizeof(base64_public_key));
        memset(base64_serial, 0, sizeof(base64_serial));

        base64_length = sizeof(base64_secret_key);
        if (base64_encode(device_entry->secret_key, device_entry->secret_key_len, base64_secret_key,
                          &base64_length))
        {
            return -1;
        }

        base64_length = sizeof(base64_public_key);
        if (base64_encode(device_entry->public_key, device_entry->public_key_len, base64_public_key,
                          &base64_length))
        {
            return -1;
        }

        base64_length = sizeof(base64_serial);
        if (base64_encode(device_entry->serial, device_entry->serial_len, base64_serial, &base64_length))
        {
            return -1;
        }

        if (device_entry->mode == DEVICE_CREDENTIALS_PSK)
        {
            mode_string = "psk";
        }
        else if (device_entry->mode == DEVICE_CREDENTIALS_CERT)
        {
            mode_string = "cert";
        }
        else if (device_entry->mode == DEVICE_CREDENTIALS_NONE)
        {
            mode_string = "none";
        }
        else
        {
            return -1;
        }

        j_entry = json_pack("{s:s, s:s, s:s, s:s, s:s, s:s}",
                            "uuid", device_entry->uuid,
                            "name", device_entry->name,
                            "mode", mode_string,
                            "secret_key", base64_secret_key,
                            "public_key", base64_public_key,
                            "serial", base64_serial);
        if (j_entry == NULL)
        {
            return -1;
        }

        if (json_array_append_new(j_array, j_entry))
        {
            json_decref(j_entry);
            return -1;
        }
    }

    return 0;
}
