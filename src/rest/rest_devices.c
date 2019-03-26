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

#include "../database.h"
#include "../punica.h"
#include "../linked_list.h"
#include "../settings.h"

static int rest_devices_save_list_to_file(linked_list_t *device_list, const char *database_file)
{
    json_t *j_database_list;

    j_database_list = json_array();

    if (j_database_list == NULL)
    {
        return -1;
    }

    if (database_list_to_json_array(device_list, j_database_list))
    {
        json_decref(j_database_list);
        return -1;
    }

    if (json_dump_file(j_database_list, database_file, 0) != 0)
    {
        json_decref(j_database_list);
        return -1;
    }

    json_decref(j_database_list);
    return 0;
}

static int rest_devices_update_list(const char *id, linked_list_t *list, const char *name)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;
    char *new_name;

    for (device_entry = list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(device_data->uuid, id) == 0)
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

static int rest_devices_remove_list(linked_list_t *list, const char *id)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;

    for (device_entry = list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(id, device_data->uuid) == 0)
        {
            linked_list_remove(list, (void *)device_data);
            database_free_entry(device_data);
            return 0;
        }
    }

    return -1;
}

static int append_server_key(json_t *j_object, const char *certificate_file)
{
    uint8_t binary_buffer[1024]; // sufficient size to store certificate
    size_t binary_length;
    static json_t *j_string;
    static bool cert_loaded = false;

    if (!json_is_object(j_object))
    {
        return -1;
    }

    if (cert_loaded == false)
    {
        binary_length = sizeof(binary_buffer);
        if (utils_load_certificate(binary_buffer, &binary_length, certificate_file))
        {
            return -1;
        }

        j_string = json_object_from_binary(binary_buffer, "server_key", binary_length);
        if (j_string == NULL)
        {
            return -1;
        }

        cert_loaded = true;
    }

    if (json_object_update(j_object, j_string))
    {
        json_decref(j_string);
        cert_loaded = false;
        return -1;
    }

    return 0;
}

static int json_object_add_string(json_t *j_object, const char *string, const char *key)
{
    json_t *j_string;

    j_string = json_object_from_string(string, key);
    if (j_string == NULL)
    {
        return -1;
    }

    if (json_object_update(j_object, j_string) != 0)
    {
        json_decref(j_string);
        return -1;
    }

    json_decref(j_string);
    return 0;
}

static int json_object_add_binary(json_t *j_object, uint8_t *buffer, const char *key, size_t buffer_length)
{
    json_t *j_binary;

    j_binary = json_object_from_binary(buffer, key, buffer_length);
    if (j_binary == NULL)
    {
        return -1;
    }

    if (json_object_update(j_object, j_binary) != 0)
    {
        json_decref(j_binary);
        return -1;
    }

    json_decref(j_binary);
    return 0;
}

static json_t *rest_devices_entry_to_resp(database_entry_t *device_entry, const char *certificate_file)
{
    json_t *j_resp_obj = NULL;
    char *mode_string;

    j_resp_obj = json_object();
    if (j_resp_obj == NULL)
    {
        return NULL;
    }

    if (device_entry->mode == DEVICE_CREDENTIALS_PSK)
    {
        mode_string = "psk";
    }
    else if (device_entry->mode == DEVICE_CREDENTIALS_CERT)
    {
        mode_string = "cert";

        if (append_server_key(j_resp_obj, certificate_file))
        {
            json_decref(j_resp_obj);
            return NULL;
        }
    }
    else if (device_entry->mode == DEVICE_CREDENTIALS_NONE)
    {
        mode_string = "none";
    }
    else
    {
        json_decref(j_resp_obj);
        return NULL;
    }

    if (json_object_add_string(j_resp_obj, device_entry->uuid, "uuid"))
    {
        json_decref(j_resp_obj);
        return NULL;
    }
    if (json_object_add_string(j_resp_obj, device_entry->name, "name"))
    {
        json_decref(j_resp_obj);
        return NULL;
    }
    if (json_object_add_string(j_resp_obj, mode_string, "mode"))
    {
        json_decref(j_resp_obj);
        return NULL;
    }
    if (json_object_add_binary(j_resp_obj, device_entry->public_key, "public_key", device_entry->public_key_len))
    {
        json_decref(j_resp_obj);
        return NULL;
    }

    return j_resp_obj;
}

static int append_client_key(json_t *j_object, database_entry_t *device_entry)
{
    json_t *j_string;

    if (!json_is_object(j_object))
    {
        return -1;
    }

    j_string = json_object_from_binary(device_entry->secret_key, "secret_key", device_entry->secret_key_len);
    if (j_string == NULL)
    {
        return -1;
    }

    if (json_object_update(j_object, j_string))
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

        j_entry_object = rest_devices_entry_to_resp(device_data, rest->settings->coap.certificate_file);
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
            j_entry_object = rest_devices_entry_to_resp(device_data, rest->settings->coap.certificate_file);
            if (j_entry_object == NULL)
            {
                ulfius_set_empty_body_response(resp, 500);
                goto exit;
            }

            ulfius_set_json_body_response(resp, 200, j_entry_object);
            json_decref(j_entry_object);
            goto exit;
        }
    }

    ulfius_set_empty_body_response(resp, 404);
exit:
    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_post_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    const char *ct;
    json_t *jdevice_list = NULL, *j_post_resp = NULL;
    database_entry_t *device_entry = NULL;

    ct = u_map_get_case(req->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(resp, 415);
        return U_CALLBACK_COMPLETE;
    }

    jdevice_list = json_loadb(req->binary_body, req->binary_body_length, 0, NULL);
    if (jdevice_list == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    if (database_validate_new_entry(jdevice_list) != 0)
    {
        ulfius_set_empty_body_response(resp, 400);
        json_decref(jdevice_list);
        return U_CALLBACK_COMPLETE;
    }

    device_entry = database_create_new_entry(jdevice_list, rest->devicesList, rest->settings->coap.certificate_file, rest->settings->coap.private_key_file);
    json_decref(jdevice_list);

    if (device_entry == NULL)
    {
        ulfius_set_empty_body_response(resp, 500);
        return U_CALLBACK_COMPLETE;
    }

    j_post_resp = rest_devices_entry_to_resp(device_entry, rest->settings->coap.certificate_file);
    if (j_post_resp == NULL)
    {
        ulfius_set_empty_body_response(resp, 500);
        database_free_entry(device_entry);
        return U_CALLBACK_COMPLETE;
    }

    if (append_client_key(j_post_resp, device_entry) != 0)
    {
        ulfius_set_empty_body_response(resp, 500);
        json_decref(j_post_resp);
        database_free_entry(device_entry);
        return U_CALLBACK_COMPLETE;
    }

    if (device_entry->mode == DEVICE_CREDENTIALS_CERT)
    {
        free(device_entry->secret_key);
        device_entry->secret_key = NULL;
        device_entry->secret_key_len = 0;
    }

    rest_lock(rest);

    linked_list_add(rest->devicesList, device_entry);
    ulfius_set_json_body_response(resp, 201, j_post_resp);
    json_decref(j_post_resp);

//  if database file not specified then only save locally
    if (rest->settings->coap.database_file)
    {
        if (rest_devices_save_list_to_file(rest->devicesList, rest->settings->coap.database_file))
        {
            log_message(LOG_LEVEL_ERROR, "[DEVICES POST] Failed to write to database file.\n");
        }
    }

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    json_t *jdevice = NULL;
    char *name;

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
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    name = string_from_json_object(jdevice, "name");
    json_decref(jdevice);

    if (name == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    rest_lock(rest);

    if (rest_devices_update_list(id, rest->devicesList, name))
    {
        ulfius_set_empty_body_response(resp, 400);
        rest_unlock(rest);
        free(name);
        return U_CALLBACK_COMPLETE;
    }

    ulfius_set_empty_body_response(resp, 201);
    free(name);

//  if database file does not exist then only save locally
    if (rest->settings->coap.database_file)
    {
        if (rest_devices_save_list_to_file(rest->devicesList, rest->settings->coap.database_file))
        {
            log_message(LOG_LEVEL_ERROR, "[DEVICES PUT] Failed to write to database file.\n");
        }
    }

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;

    const char *id;
    id = u_map_get(req->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    rest_lock(rest);

    if (rest_devices_remove_list(rest->devicesList, id))
    {
        //  device not found
        ulfius_set_empty_body_response(resp, 404);
        rest_unlock(rest);
        return U_CALLBACK_COMPLETE;
    }

    ulfius_set_empty_body_response(resp, 200);

//  if database file not specified then only save locally
    if (rest->settings->coap.database_file)
    {
        if (rest_devices_save_list_to_file(rest->devicesList, rest->settings->coap.database_file))
        {
            log_message(LOG_LEVEL_ERROR, "[DEVICES DELETE] Failed to write to database file.\n");
        }
    }

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}
