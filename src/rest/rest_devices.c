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

#include "../punica.h"
#include "../linked_list.h"
#include "../settings.h"

static int rest_devices_update_list(linked_list_t *list, const char *name, const char *uuid)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;
    char *new_name;

    for (device_entry = list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(device_data->uuid, uuid) == 0)
        {
            new_name = strdup(name);
            if (new_name == NULL)
            {
                return -1;
            }

            free(device_data->name);
            device_data->name = new_name;

            return 0;
        }
    }

    return -1;
}

static int rest_devices_remove_list(linked_list_t *list, const char *uuid)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;

    for (device_entry = list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(uuid, device_data->uuid) == 0)
        {
            linked_list_remove(list, (void *)device_data);
            database_free_entry(device_data);
            return 0;
        }
    }

    return -1;
}

static int append_server_key(json_t *j_object, void *context)
{
    uint8_t binary_buffer[1024];
    size_t binary_length;
    char base64_buffer[1024];
    size_t base64_length;
    json_t *j_string;

    if (!json_is_object(j_object))
    {
        return -1;
    }

    binary_length = sizeof(binary_buffer);
    if (utils_get_server_key(binary_buffer, &binary_length, context))
    {
        return -1;
    }

    base64_length = sizeof(base64_buffer);
    if (base64_encode(binary_buffer, binary_length, base64_buffer, &base64_length))
    {
        return -1;
    }

    j_string = json_string(base64_buffer);
    if (j_string == NULL)
    {
        return -1;
    }

    if (json_object_set_new(j_object, "server_key", j_string))
    {
        json_decref(j_string);
        return -1;
    }

    return 0;
}

static json_t *rest_devices_prepare_resp(database_entry_t *device_entry, void *context)
{
    json_t *j_resp_obj = NULL;
    json_t *uuid = NULL, *name = NULL, *mode = NULL, *public_key = NULL;
    char *mode_string;
    int ret = -1;

    j_resp_obj = json_object();
    if (j_resp_obj == NULL)
    {
        goto exit;
    }

    if (device_entry->mode == DEVICE_CREDENTIALS_PSK)
    {
        mode_string = "psk";
    }
    else if (device_entry->mode == DEVICE_CREDENTIALS_CERT)
    {
        mode_string = "cert";

        if (append_server_key(j_resp_obj, context))
        {
            goto exit;
        }
    }
    else if (device_entry->mode == DEVICE_CREDENTIALS_NONE)
    {
        mode_string = "none";
    }

    uuid = database_entry_to_json(device_entry->uuid, "uuid", BASE64_NO_ACTION, 0);
    name = database_entry_to_json(device_entry->name, "name", BASE64_NO_ACTION, 0);
    mode = database_entry_to_json(mode_string, "mode", BASE64_NO_ACTION, 0);
    public_key = database_entry_to_json(device_entry->public_key, "public_key", BASE64_ENCODE, device_entry->public_key_len);

    if ((uuid == NULL)
        || (name == NULL)
        || (mode == NULL)
        || (public_key == NULL))
    {
        goto exit;
    }

    if (json_object_update(j_resp_obj, uuid)
        || json_object_update(j_resp_obj, name)
        || json_object_update(j_resp_obj, mode)
        || json_object_update(j_resp_obj, public_key))
    {
        goto exit;
    }

    ret = 0;
exit:
    json_decref(uuid);
    json_decref(name);
    json_decref(mode);
    json_decref(public_key);
    if (ret)
    {
        json_decref(j_resp_obj);
        return NULL;
    }
    return j_resp_obj;
}

static int append_client_key(json_t *j_object, database_entry_t *device_entry)
{
    char base64_buffer[1024];
    size_t base64_length;
    json_t *j_string;

    if (!json_is_object(j_object))
    {
        return -1;
    }

    base64_length = sizeof(base64_buffer);
    if (base64_encode(device_entry->secret_key, device_entry->secret_key_len, base64_buffer, &base64_length))
    {
        return -1;
    }

    j_string = json_string(base64_buffer);
    if (j_string == NULL)
    {
        return -1;
    }

    if (json_object_set_new(j_object, "secret_key", j_string))
    {
        json_decref(j_string);
        return -1;
    }

    return 0;
}

int rest_devices_get_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    linked_list_t *device_list = rest->devicesList;
    database_entry_t *device_data;
    linked_list_entry_t *device_entry;
    json_t *j_devices = NULL;
    json_t *j_entry_object;

    rest_lock(rest);

    j_devices = json_array();
    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        j_entry_object = rest_devices_prepare_resp(device_data, context);
        if (j_entry_object == NULL)
        {
            ulfius_set_empty_body_response(resp, 500);
            goto exit;
        }

        json_array_append_new(j_devices, j_entry_object);
    }

    ulfius_set_json_body_response(resp, 200, j_devices);
exit:
    json_decref(j_devices);
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_get_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    linked_list_t *device_list = rest->devicesList;
    database_entry_t *device_data;
    linked_list_entry_t *device_entry;
    json_t *j_entry_object = NULL;

    rest_lock(rest);

    const char *id;
    id = u_map_get(req->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;
        if (strcmp(id, device_data->uuid) == 0)
        {
            j_entry_object = rest_devices_prepare_resp(device_data, context);
            if (j_entry_object == NULL)
            {
                ulfius_set_empty_body_response(resp, 500);
                goto exit;
            }

            ulfius_set_json_body_response(resp, 200, j_entry_object);
            goto exit;
        }
    }

    ulfius_set_empty_body_response(resp, 404);
exit:
    json_decref(j_entry_object);
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_post_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    const char *ct;
    json_t *jdevice_list = NULL, *jdatabase_list = NULL, *j_post_resp = NULL;
    database_entry_t *device_entry = NULL;
    int status = -1;

    rest_lock(rest);

    ct = u_map_get_case(req->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(resp, 415);
        goto exit;
    }

    jdevice_list = json_loadb(req->binary_body, req->binary_body_length, 0, NULL);
    if (database_validate_new_entry(jdevice_list, rest->devicesList))
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    device_entry = database_build_new_entry(jdevice_list, context);
    if (device_entry == NULL)
    {
        ulfius_set_empty_body_response(resp, 500);
        goto exit;
    }

    j_post_resp = rest_devices_prepare_resp(device_entry, context);
    if (j_post_resp == NULL)
    {
        ulfius_set_empty_body_response(resp, 500);
        goto exit;
    }

    if (append_client_key(j_post_resp, device_entry))
    {
        goto exit;
    }

    if (device_entry->mode == DEVICE_CREDENTIALS_CERT)
    {
        free(device_entry->secret_key);
        device_entry->secret_key = NULL;
        device_entry->secret_key_len = 0;
    }

    linked_list_add(rest->devicesList, device_entry);
    status = 0;

//  if database file not specified then only save locally
    if (rest->settings->coap.database_file)
    {
        jdatabase_list = json_array();

        if (database_prepare_array(jdatabase_list, rest->devicesList))
        {
            ulfius_set_json_body_response(resp, 500, j_post_resp);
            goto exit;
        }

        if (json_dump_file(jdatabase_list, rest->settings->coap.database_file, 0) != 0)
        {
            ulfius_set_json_body_response(resp, 500, j_post_resp);
            goto exit;
        }
    }

    ulfius_set_json_body_response(resp, 201, j_post_resp);
exit:
    if (status)
    {
        database_free_entry(device_entry);
    }
    json_decref(jdevice_list);
    json_decref(jdatabase_list);
    json_decref(j_post_resp);
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    json_t *jdevice = NULL, *jdatabase_list = NULL, *j_string = NULL;
    const char *name;

    rest_lock(rest);

    const char *ct;
    ct = u_map_get_case(req->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(resp, 415);
        goto exit;
    }

    const char *uuid;
    uuid = u_map_get(req->map_url, "id");
    if (uuid == NULL)
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

    j_string = json_object_get(jdevice, "name");
    if (j_string == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    name = json_string_value(j_string);
    if (name == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    if (rest_devices_update_list(rest->devicesList, name, uuid))
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
    json_decref(j_string);
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    json_t *jdatabase_list = NULL;

    rest_lock(rest);

    const char *uuid;
    uuid = u_map_get(req->map_url, "id");
    if (uuid == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        goto exit;
    }

    if (rest_devices_remove_list(rest->devicesList, uuid))
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
