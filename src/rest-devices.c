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
#include "rest-list.h"
#include "settings.h"

static int rest_devices_update_list(rest_list_t *list, json_t *jdevice)
{
    const char *string;
    json_t *jstring;
    rest_list_entry_t *device_entry;
    database_entry_t *device_data;
    uint8_t *oldpsk, *oldid;
    uint8_t binary_buffer[512];
    size_t length;

    jstring = json_object_get(jdevice, "uuid");
    string = json_string_value(jstring);

    for (device_entry = list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(device_data->uuid, string) == 0)
        {
            jstring = json_object_get(jdevice, "psk");
            string = json_string_value(jstring);

            base64_decode(string, NULL, &length);
            if (base64_decode(string, binary_buffer, &length))
            {
                return -1;
            }

            oldpsk = device_data->psk;
            device_data->psk = malloc(length);
            if (device_data->psk == NULL)
            {
                device_data->psk = oldpsk;
                return -1;
            }
            memcpy(device_data->psk, binary_buffer, length);

            jstring = json_object_get(jdevice, "psk_id");
            string = json_string_value(jstring);

            base64_decode(string, NULL, &length);
            if (base64_decode(string, binary_buffer, &length))
            {
                return -1;
            }

            oldid = device_data->psk_id;
            device_data->psk_id = malloc(length);
            if (device_data->psk_id == NULL)
            {
                free(device_data->psk);
                device_data->psk = oldpsk;
                device_data->psk_id = oldid;
                return -1;
            }
            memcpy(device_data->psk_id, binary_buffer, length);
            free(oldpsk);
            free(oldid);

            return 0;
        }
    }

    return -1;
}

static int rest_devices_remove_list(rest_list_t *list, const char *id)
{
    rest_list_entry_t *device_entry;
    database_entry_t *device_data;

    for (device_entry = list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(id, device_data->uuid) == 0)
        {
            rest_list_remove(list, (void *)device_data);
            return 0;
        }
    }

    return -1;
}

int rest_devices_get_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    rest_list_t *device_list = rest->devicesList;
    char string[512];
    size_t length;
    database_entry_t *device_data;
    rest_list_entry_t *device_entry;
    json_t *jdevices = NULL;

    rest_lock(rest);

    jdevices = json_array();
    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;
        length = sizeof(string);
        memset(string, 0, length);

        if (base64_encode(device_data->psk_id, device_data->psk_id_len, string, &length))
        {
            ulfius_set_empty_body_response(resp, 500);
            goto exit;
        }

        json_t *jstring = json_string(string);
        json_t *jobject = json_object();
        json_object_set_new(jobject, "psk_id", jstring);
        json_array_append_new(jdevices, jobject);
    }

    ulfius_set_json_body_response(resp, 200, jdevices);
exit:
    json_decref(jdevices);
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_get_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    rest_list_t *device_list = rest->devicesList;
    char string[512];
    size_t length = sizeof(string);
    database_entry_t *device_data;
    rest_list_entry_t *device_entry;
    json_t *jdevice = NULL;

    rest_lock(rest);

    const char *id;
    id = u_map_get(req->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    jdevice = json_object();
    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;
        if (strcmp(id, device_data->uuid) == 0)
        {
            memset(string, 0, length);

            if (base64_encode(device_data->psk_id, device_data->psk_id_len, string, &length))
            {
                ulfius_set_empty_body_response(resp, 500);
                goto exit;
            }

            json_t *jstring = json_string(string);
            json_object_set_new(jdevice, "psk_id", jstring);
            ulfius_set_json_body_response(resp, 200, jdevice);

            goto exit;
        }
    }

    ulfius_set_empty_body_response(resp, 404);
exit:
    json_decref(jdevice);
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    const char *ct;
    json_t *jdevice_list = NULL, *jdatabase_list = NULL;
    database_entry_t *device_entry;

    rest_lock(rest);

    ct = u_map_get_case(req->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(resp, 415);
        goto exit;
    }

    jdevice_list = json_loadb(req->binary_body, req->binary_body_length, 0, NULL);
    if (database_validate_entry(jdevice_list))
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    device_entry = calloc(1, sizeof(database_entry_t));
    if (device_entry == NULL)
    {
        ulfius_set_empty_body_response(resp, 500);
        goto exit;
    }

    if (database_populate_entry(jdevice_list, device_entry))
    {
        ulfius_set_empty_body_response(resp, 500);
        goto exit;
    }
    rest_list_add(rest->devicesList, device_entry);

//  if database file not specified then only save locally
    if (rest->settings->coap.database_file)
    {
        jdatabase_list = json_array();

        if (database_prepare_array(jdatabase_list, rest->devicesList))
        {
            ulfius_set_empty_body_response(resp, 500);
            goto exit;
        }

        if (json_dump_file(jdatabase_list, rest->settings->coap.database_file, 0) != 0)
        {
            ulfius_set_empty_body_response(resp, 500);
            goto exit;
        }
    }

    ulfius_set_empty_body_response(resp, 201);
exit:
    json_decref(jdevice_list);
    json_decref(jdatabase_list);
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_post_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    json_t *jdevice = NULL, *jdatabase_list = NULL;

    rest_lock(rest);

    const char *ct;
    ct = u_map_get_case(req->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(resp, 415);
        goto exit;
    }

    const char *id;
    id = u_map_get(req->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    jdevice = json_loadb(req->binary_body, req->binary_body_length, 0, NULL);
    if (!json_is_object(jdevice))
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }
    if ((json_object_get(jdevice, "psk") == NULL) || (json_object_get(jdevice, "psk_id") == NULL))
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    json_t *jstring = json_string(id);
    json_object_set_new(jdevice, "uuid", jstring);

    // if later stages fail, global list will be updated, but database file not
    // consider updating list at the end
    if (rest_devices_update_list(rest->devicesList, jdevice))
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

//  if database file does not exist then only save locally
    if (rest->settings->coap.database_file == NULL)
    {
        ulfius_set_empty_body_response(resp, 201);
        goto exit;
    }

    jdatabase_list = json_array();

    if (database_prepare_array(jdatabase_list, rest->devicesList))
    {
        ulfius_set_empty_body_response(resp, 500);
        goto exit;
    }

    if (json_dump_file(jdatabase_list, rest->settings->coap.database_file, 0) != 0)
    {
        ulfius_set_empty_body_response(resp, 500);
        goto exit;
    }

    ulfius_set_empty_body_response(resp, 201);
exit:
    json_decref(jdevice);
    json_decref(jdatabase_list);
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    json_t *jdatabase_list = NULL;

    rest_lock(rest);

    const char *id;
    id = u_map_get(req->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    if (rest_devices_remove_list(rest->devicesList, id))
    {
        //  device not found
        ulfius_set_empty_body_response(resp, 404);
        goto exit;
    }
//  if database file not specified then only save locally
    if (rest->settings->coap.database_file == NULL)
    {
        ulfius_set_empty_body_response(resp, 200);
        goto exit;
    }

    jdatabase_list = json_array();

    if (database_prepare_array(jdatabase_list, rest->devicesList))
    {
        ulfius_set_empty_body_response(resp, 500);
        goto exit;
    }

    if (json_dump_file(jdatabase_list, rest->settings->coap.database_file, 0) != 0)
    {
        ulfius_set_empty_body_response(resp, 500);
        goto exit;
    }

    ulfius_set_empty_body_response(resp, 200);
exit:
    json_decref(jdatabase_list);
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}
