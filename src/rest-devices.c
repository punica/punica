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

#include "restserver.h"
#include "settings.h"

static device_database_t *rest_devices_prepare_list(json_t *array)
{
    const char *string;
    int count;
    size_t index;
    json_t *value, *key;
    device_database_t *entry, *head = NULL;
    uint8_t binary_buffer[512];
    size_t length;

    entry = alloc_device_list(json_array_size(array));
    if (entry == NULL)
    {
        return NULL;
    }
    head = entry;

    json_array_foreach(array, index, value)
    {
        count = 0;
        if ((key = json_object_get(value, "uuid")) != NULL)
        {
            string = json_string_value(key);
            if (string == NULL)
            {
                goto abort;
            }

            entry->uuid = (char *)malloc(strlen(string) + 1);
            if (entry->uuid == NULL)
            {
                goto abort;
            }

            memcpy(entry->uuid, string, strlen(string) + 1);
            count++;
        }
        if ((key = json_object_get(value, "psk")) != NULL)
        {
            string = json_string_value(key);
            if (string == NULL)
            {
                goto abort;
            }

            if (base64_decode(string, NULL, &length))
            {
                goto abort;
            }

            if (base64_decode(string, binary_buffer, &length))
            {
                goto abort;
            }

            entry->psk = (uint8_t *)malloc(length);
            if (entry->psk == NULL)
            {
                goto abort;
            }

            memcpy(entry->psk, binary_buffer, length);
            entry->psk_len = length;
            count++;
        }
        if ((key = json_object_get(value, "psk_id")) != NULL)
        {
            string = json_string_value(key);
            if (string == NULL)
            {
                goto abort;
            }

            if (base64_decode(string, NULL, &length))
            {
                goto abort;
            }

            if (base64_decode(string, binary_buffer, &length))
            {
                goto abort;
            }

            entry->psk_id = (uint8_t *)malloc(length);
            if (entry->psk_id == NULL)
            {
                goto abort;
            }

            memcpy(entry->psk_id, binary_buffer, length);
            entry->psk_id_len = length;
            count++;
        }

abort:
        entry = entry->next;

        if (count != 3)
        {
            free_device_list(head);
            return NULL;
        }
    }

    return head;
}

static int rest_devices_update_list(device_database_t *list, json_t *jdevice)
{
    if (list == NULL || jdevice == NULL)
    {
        return -1;
    }

    const char *string;
    json_t *jstring;
    device_database_t *device;
    uint8_t *oldpsk, *oldid;
    uint8_t binary_buffer[512];
    size_t length;

    jstring = json_object_get(jdevice, "uuid");
    string = json_string_value(jstring);

    for (device = list; device != NULL; device = device->next)
    {
        if (strcmp(device->uuid, string) == 0)
        {
            jstring = json_object_get(jdevice, "psk");
            string = json_string_value(jstring);

            base64_decode(string, NULL, &length);
            if (base64_decode(string, binary_buffer, &length))
            {
                return -1;
            }

            oldpsk = device->psk;
            device->psk = malloc(length);
            if (device->psk == NULL)
            {
                device->psk = oldpsk;
                return -1;
            }
            memcpy(device->psk, binary_buffer, length);

            jstring = json_object_get(jdevice, "psk_id");
            string = json_string_value(jstring);

            base64_decode(string, NULL, &length);
            if (base64_decode(string, binary_buffer, &length))
            {
                return -1;
            }

            oldid = device->psk_id;
            device->psk_id = malloc(length);
            if (device->psk_id == NULL)
            {
                free(device->psk);
                device->psk = oldpsk;
                device->psk_id = oldid;
                return -1;
            }
            memcpy(device->psk_id, binary_buffer, length);
            free(oldpsk);
            free(oldid);

            return 0;
        }
    }

    return -1;
}

static int rest_devices_remove_list(device_database_t **list, const char *id)
{
    if (*list == NULL || id == NULL)
    {
        return -1;
    }

    device_database_t *prev = NULL, *curr;
    curr = *list;

    while (curr != NULL)
    {
        if (strcmp(id, curr->uuid) == 0)
        {
            if (curr == *list)
            {
                *list = curr->next;
                return 0;
            }
            prev->next = curr->next;
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }

    return -1;
}

int rest_devices_get_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    coap_settings_t *data = (coap_settings_t *)context;
    device_database_t *device;
    char string[512];
    size_t length;

    json_t *jdevices = json_array();
    for (device = data->security; device != NULL; device = device->next)
    {
        length = sizeof(string);
        memset(string, 0, length);

        if (base64_encode(device->psk_id, device->psk_id_len, string, &length))
        {
            json_decref(jdevices);
            ulfius_set_empty_body_response(resp, 500);
            return U_CALLBACK_COMPLETE;
        }

        json_t *jstring = json_string(string);
        json_array_append_new(jdevices, jstring);
    }

    ulfius_set_json_body_response(resp, 200, jdevices);
    json_decref(jdevices);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_get_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    coap_settings_t *data = (coap_settings_t *)context;
    device_database_t *device;
    char string[512];
    size_t length = sizeof(string);

    const char *id;
    id = u_map_get(req->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    json_t *jdevice = json_object();
    for (device = data->security; device != NULL; device = device->next)
    {
        if (strcmp(id, device->uuid) == 0)
        {
            memset(string, 0, length);

            if (base64_encode(device->psk_id, device->psk_id_len, string, &length))
            {
                json_decref(jdevice);
                ulfius_set_empty_body_response(resp, 500);
                return U_CALLBACK_COMPLETE;
            }

            json_t *jstring = json_string(string);
            json_object_set_new(jdevice, "psk_id", jstring);
            ulfius_set_json_body_response(resp, 200, jdevice);
            json_decref(jdevice);

            return U_CALLBACK_COMPLETE;
        }
    }

    ulfius_set_empty_body_response(resp, 404);
    json_decref(jdevice);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    coap_settings_t *data = (coap_settings_t *)context;
    const char *ct;
    json_t *jdevice_list, *jdatabase_list;

    ct = u_map_get_case(req->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(resp, 415);
        return U_CALLBACK_COMPLETE;
    }

    jdevice_list = json_loadb(req->binary_body, req->binary_body_length, 0, NULL);
    if (!json_is_array(jdevice_list))
    {
        json_decref(jdevice_list);
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    device_database_t *device_list;
    if ((device_list = rest_devices_prepare_list(jdevice_list)) == NULL)
    {
        json_decref(jdevice_list);
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

//  if database file not specified then only save locally
    if (data->database_file)
    {
        jdatabase_list = json_load_file(data->database_file, 0, NULL);
        if (json_is_array(jdatabase_list) != 0)
        {
            json_array_extend(jdatabase_list, jdevice_list);
 
            if (json_dump_file(jdatabase_list, data->database_file, 0) != 0)
            {
                free(device_list);
                json_decref(jdevice_list);
                json_decref(jdatabase_list);
                ulfius_set_empty_body_response(resp, 500);
                return U_CALLBACK_COMPLETE;
            }
        }
        else
        {
//          file does not exist
            if (json_dump_file(jdevice_list, data->database_file, 0) != 0)
            {
                free(device_list);
                json_decref(jdevice_list);
                json_decref(jdatabase_list);
                ulfius_set_empty_body_response(resp, 500);
                return U_CALLBACK_COMPLETE;
            }
        }
    }

    if (data->security == NULL)
    {
        data->security = device_list;
    }
    else
    {
        device_database_t *entry = data->security;
        while (entry->next != NULL)
        {
            entry = entry->next;
        }
        entry->next = device_list;
    }

    ulfius_set_empty_body_response(resp, 201);
    json_decref(jdevice_list);
    json_decref(jdatabase_list);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_post_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    coap_settings_t *data = (coap_settings_t *)context;
    json_t *jdevice, *jdatabase_list;

    const char *ct;
    ct = u_map_get_case(req->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(resp, 415);
        return U_CALLBACK_COMPLETE;
    }

    const char *id;
    id = u_map_get(req->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    jdevice = json_loadb(req->binary_body, req->binary_body_length, 0, NULL);
    if (!json_is_object(jdevice))
    {
        json_decref(jdevice);
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }
    if ((json_object_get(jdevice, "psk") == NULL) || (json_object_get(jdevice, "psk_id") == NULL))
    {
        json_decref(jdevice);
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    json_t *jstring = json_string(id);
    json_object_set_new(jdevice, "uuid", jstring);

    // if later stages fail, global list will be updated, but database file not
    // consider updating list at the end
    if (rest_devices_update_list(data->security, jdevice))
    {
        json_decref(jdevice);
        ulfius_set_empty_body_response(resp, 500);
        return U_CALLBACK_COMPLETE;
    }

//  if database file does not exit then only save locally
    if (data->database_file)
    {
        json_decref(jdevice);
        ulfius_set_empty_body_response(resp, 201);
        return U_CALLBACK_COMPLETE;
    }

    jdatabase_list = json_load_file(data->database_file, 0, NULL);
    if (jdatabase_list == NULL)
    {
        // file hasn't been created
        json_decref(jdevice);
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_COMPLETE;
    }
    else if (!json_is_array(jdatabase_list))
    {
        // file exists, but is not an array
        json_decref(jdevice);
        json_decref(jdatabase_list);
        ulfius_set_empty_body_response(resp, 500);
        return U_CALLBACK_COMPLETE;
    }

    size_t index;
    json_t *jobject, *jkey;
    json_array_foreach(jdatabase_list, index, jobject)
    {
        jkey = json_object_get(jobject, "uuid");

//      continue in case database file contains errors
        if (jkey == NULL)
        {
            continue;
        }

        if (strcmp(json_string_value(jkey), id) == 0)
        {
            json_array_set(jdatabase_list, index, jdevice);
            break;
        }
    }

    if (json_dump_file(jdatabase_list, data->database_file, 0) != 0)
    {
        json_decref(jdevice);
        json_decref(jdatabase_list);
        ulfius_set_empty_body_response(resp, 500);
        return U_CALLBACK_COMPLETE;
    }

    ulfius_set_empty_body_response(resp, 201);
    json_decref(jdevice);
    json_decref(jdatabase_list);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    int ret = 404;
    coap_settings_t *data = (coap_settings_t *)context;
    json_t *jdatabase_list;

    const char *id;
    id = u_map_get(req->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    if (rest_devices_remove_list(&data->security, id))
    {
        //  device not found
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_COMPLETE;
    }

    jdatabase_list = json_load_file(data->database_file, 0, NULL);
    if (json_is_array(jdatabase_list) == 0)
    {
        ret = 400;
        goto exit;
    }

    size_t index;
    json_t *j_value, *j_entry;
    const char *j_string;
    json_array_foreach(jdatabase_list, index, j_value)
    {
//      if error continue in case there are errors in database file
        j_entry = json_object_get(j_value, "uuid");
        if (j_entry == NULL)
        {
            continue;
        }

        j_string = json_string_value(j_entry);
        if (j_string == NULL)
        {
            continue;
        }

        if (strcmp(j_string, id) != 0)
        {
            continue;
        }

        json_array_remove(jdatabase_list, index);
        json_dump_file(jdatabase_list, data->database_file, 0);
        ret = 200;
        goto exit;
    }

exit:
    json_decref(jdatabase_list);
    ulfius_set_empty_body_response(resp, ret);
    return U_CALLBACK_COMPLETE;
}
