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
#include "rest/rest_core_types.h"
#include "linked_list.h"
#include "punica.h"

#define DATABASE_UUID_KEY_BIT       0x01
#define DATABASE_MODE_KEY_BIT       0x02
#define DATABASE_NAME_KEY_BIT       0x04
#define DATABASE_PUBLIC_KEY_BIT     0x08
#define DATABASE_SECRET_KEY_BIT     0x10
#define DATABASE_SERIAL_KEY_BIT     0x20
#define DATABASE_ALL_NEW_KEYS_SET   0x06
#define DATABASE_ALL_KEYS_SET       0x3F

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
        if (database_validate_entry(j_entry, device_list))
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

json_t *database_entry_to_json(void *entry, const char *key, database_base64_action action,
                               size_t entry_size)
{
    json_t *j_object = NULL, *j_string = NULL;
    char base64_string[1024] = {0};
    size_t base64_length = sizeof(base64_string);
    int status = -1;

    j_object = json_object();
    if (j_object == NULL)
    {
        goto exit;
    }

    if (action == BASE64_NO_ACTION)
    {
        j_string = json_string((const char *)entry);
        if (j_string == NULL)
        {
            goto exit;
        }

        if (json_object_set_new(j_object, key, j_string))
        {
            json_decref(j_string);
            goto exit;
        }
    }
    else if (action == BASE64_ENCODE)
    {
        if (base64_encode(entry, entry_size, base64_string, &base64_length))
        {
            goto exit;
        }

        j_string = json_string((const char *)base64_string);
        if (j_string == NULL)
        {
            goto exit;
        }

        if (json_object_set_new(j_object, key, j_string))
        {
            json_decref(j_string);
            goto exit;
        }
    }
    else
    {
        goto exit;
    }

    status = 0;
exit:
    if (status)
    {
        json_decref(j_object);
        return NULL;
    }
    return j_object;
}

void *database_json_to_entry(json_t *j_object, const char *key,
                             database_base64_action base64_action, size_t *entry_size)
{
    json_t *j_value;
    const char *json_string;
    size_t binary_length;
    void *entry = NULL;
    int status = -1;

    j_value = json_object_get(j_object, key);
    if (j_value == NULL)
    {
        goto exit;
    }

    json_string = json_string_value(j_value);
    if (json_string == NULL)
    {
        goto exit;
    }

    if (base64_action == BASE64_NO_ACTION)
    {
        entry = strdup(json_string);
        if (entry == NULL)
        {
            goto exit;
        }
        if (entry_size)
        {
            *entry_size = strlen(entry) + 1;
        }
    }
    else if (base64_action == BASE64_DECODE)
    {
        if (base64_decode(json_string, NULL, &binary_length))
        {
            goto exit;
        }

        entry = malloc(binary_length);
        if (entry == NULL)
        {
            goto exit;
        }

        if (base64_decode(json_string, entry, &binary_length))
        {
            goto exit;
        }

        *entry_size = binary_length;
    }
    else
    {
        goto exit;
    }

    status = 0;
exit:
    if (status)
    {
        free(entry);
        return NULL;
    }
    return entry;
}

database_entry_t *database_get_entry_by_name(linked_list_t *device_list, const char *name)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;

    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(name, device_data->name) == 0)
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
        free(device_entry->uuid);
        free(device_entry->name);
        free(device_entry->public_key);
        free(device_entry->secret_key);

        free(device_entry);
    }
}

int database_validate_new_entry(json_t *j_new_device_object, linked_list_t *device_list)
{
    int key_check = 0;
    const char *key, *value_string;
    json_t *j_value;
    database_entry_t *device_entry;

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

            if (strcasecmp(value_string, "psk")
                && strcasecmp(value_string, "cert")
                && strcasecmp(value_string, "none"))
            {
                return -1;
            }

            key_check |= DATABASE_MODE_KEY_BIT;
        }
        else if (strcasecmp(key, "name") == 0)
        {
            value_string = json_string_value(j_value);

            device_entry = database_get_entry_by_name(device_list, value_string);
            if (device_entry != NULL)
            {
                return -1;
            }

            key_check |= DATABASE_NAME_KEY_BIT;
        }
    }

    if (key_check != DATABASE_ALL_NEW_KEYS_SET)
    {
        return -1;
    }

    return 0;
}

int database_validate_entry(json_t *j_device_object, linked_list_t *device_list)
{
    int key_check = 0;
    const char *key, *value_string;
    json_t *j_value;
    uint8_t buffer[512];
    size_t buffer_len = sizeof(buffer);
    int ret;
    database_entry_t *device_entry;

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

            device_entry = database_get_entry_by_name(device_list, value_string);
            if (device_entry != NULL)
            {
                return -1;
            }

            key_check |= DATABASE_NAME_KEY_BIT;
        }
        else if (strcasecmp(key, "mode") == 0)
        {
            value_string = json_string_value(j_value);

            if (strcasecmp(value_string, "psk")
                && strcasecmp(value_string, "cert")
                && strcasecmp(value_string, "none"))
            {
                return -1;
            }

            key_check |= DATABASE_MODE_KEY_BIT;
        }
        else if (strcasecmp(key, "public_key") == 0)
        {
            ret = base64_decode(json_string_value(j_value), buffer, &buffer_len);
            if ((ret != BASE64_ERR_NONE) &&
                (ret != BASE64_ERR_ARG)) // key might contain string with length of zero
            {
                return -1;
            }
            key_check |= DATABASE_PUBLIC_KEY_BIT;
        }
        else if (strcasecmp(key, "secret_key") == 0)
        {
            ret = base64_decode(json_string_value(j_value), buffer, &buffer_len);
            if ((ret != BASE64_ERR_NONE) && (ret != BASE64_ERR_ARG))
            {
                return -1;
            }
            key_check |= DATABASE_SECRET_KEY_BIT;
        }
        else if (strcasecmp(key, "serial") == 0)
        {
            ret = base64_decode(json_string_value(j_value), buffer, &buffer_len);
            if ((ret != BASE64_ERR_NONE) && (ret != BASE64_ERR_ARG))
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
    const char *mode;
    int status = -1;
    database_entry_t *device_entry = NULL;

    if (j_device_object == NULL)
    {
        goto exit;
    }

    device_entry = calloc(1, sizeof(database_entry_t));
    if (device_entry == NULL)
    {
        goto exit;
    }

    mode = database_json_to_entry(j_device_object, "mode", BASE64_NO_ACTION, NULL);
    if (mode == NULL)
    {
        goto exit;
    }

    if (strcasecmp(mode, "psk") == 0)
    {
        device_entry->mode = DEVICE_CREDENTIALS_PSK;
    }
    else if (strcasecmp(mode, "cert") == 0)
    {
        device_entry->mode = DEVICE_CREDENTIALS_CERT;
    }
    else if (strcasecmp(mode, "none") == 0)
    {
        device_entry->mode = DEVICE_CREDENTIALS_NONE;
    }
    else
    {
        goto exit;
    }

    device_entry->uuid = database_json_to_entry(j_device_object, "uuid", BASE64_NO_ACTION, NULL);
    device_entry->name = database_json_to_entry(j_device_object, "name", BASE64_NO_ACTION, NULL);
    device_entry->public_key = database_json_to_entry(j_device_object, "public_key", BASE64_DECODE,
                                                      &device_entry->public_key_len);
    device_entry->secret_key = database_json_to_entry(j_device_object, "secret_key", BASE64_DECODE,
                                                      &device_entry->secret_key_len);
    device_entry->serial = database_json_to_entry(j_device_object, "serial", BASE64_DECODE,
                                                  &device_entry->serial_len);

    if (device_entry->uuid == NULL
        || device_entry->name == NULL
        || (device_entry->mode ==
            DEVICE_CREDENTIALS_PSK // some entry types must contain keys that other don't
            && (device_entry->secret_key == NULL
                || device_entry->public_key == NULL))
        || (device_entry->mode == DEVICE_CREDENTIALS_CERT
            && (device_entry->serial == NULL
                || device_entry->public_key == NULL)))
    {
        goto exit;
    }

    status = 0;
exit:
    if (status)
    {
        database_free_entry(device_entry);
        device_entry = NULL;
    }
    return device_entry;
}

database_entry_t *database_create_new_entry(json_t *j_device_object, void *context)
{
    uuid_t b_uuid;
    char *uuid = NULL;
    char *mode;
    int status = -1;
    database_entry_t *device_entry = NULL;

    if (j_device_object == NULL)
    {
        goto exit;
    }

    device_entry = calloc(1, sizeof(database_entry_t));
    if (device_entry == NULL)
    {
        goto exit;
    }

    mode = database_json_to_entry(j_device_object, "mode", BASE64_NO_ACTION, NULL);
    if (mode == NULL)
    {
        goto exit;
    }

    if (strcasecmp(mode, "psk") == 0)
    {
        device_entry->mode = DEVICE_CREDENTIALS_PSK;
    }
    else if (strcasecmp(mode, "cert") == 0)
    {
        device_entry->mode = DEVICE_CREDENTIALS_CERT;
    }
    else if (strcasecmp(mode, "none") == 0)
    {
        device_entry->mode = DEVICE_CREDENTIALS_NONE;
    }
    else
    {
        goto exit;
    }

    device_entry->name = database_json_to_entry(j_device_object, "name", BASE64_NO_ACTION, NULL);
    if (device_entry->name == NULL)
    {
        goto exit;
    }

    uuid_generate_random(b_uuid);

    uuid = malloc(37);
    if (uuid == NULL)
    {
        goto exit;
    }

    uuid_unparse(b_uuid, uuid);

    device_entry->uuid = strdup(uuid);
    if (device_entry->uuid == NULL)
    {
        goto exit;
    }

    if (device_new_credentials(device_entry, context))
    {
        goto exit;
    }

    status = 0;
exit:
    if (status)
    {
        database_free_entry(device_entry);
        device_entry = NULL;
    }
    free(uuid);
    free(mode);
    return device_entry;
}

int database_list_to_json_array(linked_list_t *device_list, json_t *j_array)
{
    linked_list_entry_t *list_entry;
    database_entry_t *device_entry;
    json_t *j_entry;
    char base64_secret_key[1024];
    char base64_public_key[1024];
    char base64_serial[64];
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
