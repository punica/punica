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

#include "restserver.h"
#include "settings.h"

static void abort_list(device_database_t *list)
{
    device_database_t *next, *curr;

    for(curr = list; curr != NULL; )
    {
        next = curr->next;
        free(curr);
        curr = next;
    }
}

static int update_list(device_database_t *list, json_t *array)
{
    const char* string;
    int count;
    size_t index;
    json_t *value, *key;
    device_database_t *entry, *head = NULL;

    json_array_foreach(array, index, value)
    {
        count = 0;
        entry = (device_database_t*)malloc(sizeof(device_database_t));
        memset(entry, 0, sizeof(device_database_t));

        if((key = json_object_get(value, "uuid")) != NULL)
        {
            string = json_string_value(key);
            if(string == NULL)
                goto abort;

            memcpy(entry->uuid, string, strlen(string) + 1);
            count++;
        }
        if((key = json_object_get(value, "psk")) != NULL)
        {
            string = json_string_value(key);
            if(string == NULL)
                goto abort;

            memcpy(entry->uuid, string, strlen(string) + 1);
            count++;
        }
        if((key = json_object_get(value, "psk_id")) != NULL)
        {
            string = json_string_value(key);
            if(string == NULL)
                goto abort;

            memcpy(entry->uuid, string, strlen(string) + 1);
            count++;
        }

abort:
        entry->next = head;
        head = entry;

        if(count != 3)
        {
            abort_list(head);
            return 1;
        }
    }

    head = entry;
    while(entry->next != NULL)
    {
        entry = entry->next;
    }
    entry->next = list;
    list = head;

    return 0;
}

int rest_devices_get_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    coap_settings_t *data = (rest_context_t *)context;
    device_database_t *device;

    json_t *jdevices = json_array();
    for (device = data->security; device != NULL; device = device->next)
    {
        json_t *jstring = json_string(device->uuid);
        json_array_append_new(jdevices, jstring);
    }

    ulfius_set_json_body_response(resp, 200, jdevices);
    json_decref(jdevices);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    coap_settings_t *data = (rest_context_t *)context;
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

    if(update_list(data->security, jdevice_list))
    {
        json_decref(jdevice_list);
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    jdatabase_list = json_load_file(data->database_file, 0, NULL);
    json_array_extend(jdatabase_list, jdevice_list);

    if(json_dump_file(jdatabase_list, data->database_file, 0) != NULL)
    {
        json_decref(jdevice_list);
        json_decref(jdatabase_list);
        ulfius_set_empty_body_response(resp, 500);
        return U_CALLBACK_COMPLETE;
    }

    ulfius_set_empty_body_response(resp, 201);
    json_decref(jdevice_list);
    json_decref(jdatabase_list);

    return U_CALLBACK_COMPLETE;
}

