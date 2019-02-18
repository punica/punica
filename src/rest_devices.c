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

#include "devices_database.h"
#include "http_codes.h"
#include "linked_list.h"
#include "punica.h"
#include "rest_callbacks.h"

int rest_devices_get_cb(const struct _u_request *u_request,
                        struct _u_response *u_response, void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    json_t *j_devices = json_array();

    punica_lock(punica);

    if (devices_database_to_public_json(punica->rest_devices,
                                        j_devices) != 0)
    {
        ulfius_set_empty_body_response(u_response,
                                       HTTP_500_INTERNAL_ERROR);
    }
    else
    {
        ulfius_set_json_body_response(u_response, HTTP_200_OK, j_devices);
        json_decref(j_devices);
    }

    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_get_name_cb(const struct _u_request *u_request,
                             struct _u_response *u_response,
                             void *context)
{
    punica_context_t *punica = (punica_context_t *) context;
    database_entry_t *device;
    json_t *j_body = NULL;
    const char *uuid;

    uuid = u_map_get(u_request->map_url, "uuid");
    if (uuid == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        return U_CALLBACK_COMPLETE;
    }

    punica_lock(punica);

    device = devices_database_get_by_uuid(punica->rest_devices, uuid);
    if (device == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
    }
    else
    {
        j_body = devices_database_entry_get_public_json(device);

        if (j_body == NULL)
        {
            ulfius_set_empty_body_response(u_response,
                                           HTTP_500_INTERNAL_ERROR);
        }
        else
        {
            ulfius_set_json_body_response(u_response,
                                          HTTP_200_OK, j_body);
            json_decref(j_body);
        }
    }

    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_post_cb(const struct _u_request *u_request,
                         struct _u_response *u_response,
                         void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    json_t *j_device = NULL, *j_body;
    database_entry_t *device;
    const char *content_type;

    content_type = u_map_get_case(u_request->map_header, "Content-Type");
    if (content_type == NULL
        || strcmp(content_type, "application/json") != 0)
    {
        ulfius_set_empty_body_response(u_response,
                                       HTTP_415_UNSUPPORTED_MEDIA_TYPE);
        return U_CALLBACK_COMPLETE;
    }

    j_device = json_loadb(u_request->binary_body,
                          u_request->binary_body_length, 0, NULL);
    if (devices_database_new_entry_validate(j_device))
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        return U_CALLBACK_COMPLETE;
    }

    device = malloc(sizeof(database_entry_t));
    if (device == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        json_decref(j_device);
        return U_CALLBACK_COMPLETE;
    }

    if (devices_database_entry_new_from_json(j_device, device) != 0)
    {
        free(device);
        json_decref(j_device);
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        return U_CALLBACK_COMPLETE;
    }
    json_decref(j_device);

    punica_lock(punica);
    linked_list_add(punica->rest_devices, device);

    devices_database_to_file(punica->rest_devices,
                             punica->settings->coap.database_file);
    punica_unlock(punica);

    j_body = devices_database_entry_get_json(device);
    if (j_body == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        return U_CALLBACK_COMPLETE;
    }

    ulfius_set_json_body_response(u_response, HTTP_201_CREATED, j_body);
    json_decref(j_body);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_put_cb(const struct _u_request *u_request,
                        struct _u_response *u_response, void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    json_t *j_device = NULL;
    database_entry_t *device = NULL;
    const char *content_type, *uuid;

    content_type = u_map_get_case(u_request->map_header, "Content-Type");
    if (content_type == NULL
        || strcmp(content_type, "application/json") != 0)
    {
        ulfius_set_empty_body_response(u_response,
                                       HTTP_415_UNSUPPORTED_MEDIA_TYPE);
        return U_CALLBACK_COMPLETE;
    }

    uuid = u_map_get(u_request->map_url, "uuid");
    if (uuid == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        return U_CALLBACK_COMPLETE;
    }

    j_device = json_loadb(u_request->binary_body,
                          u_request->binary_body_length, 0, NULL);
    if (!json_is_object(j_device))
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        return U_CALLBACK_COMPLETE;
    }

    if (devices_database_new_entry_validate(j_device) != 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        json_decref(j_device);
        return U_CALLBACK_COMPLETE;
    }

    json_object_set_new(j_device, "uuid", json_string(uuid));

    device = malloc(sizeof(database_entry_t));
    if (device == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        json_decref(j_device);
        return U_CALLBACK_COMPLETE;
    }

    if (devices_database_entry_from_json(j_device, device) != 0)
    {
        free(device);
        json_decref(j_device);
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        return U_CALLBACK_COMPLETE;
    }
    json_decref(j_device);

    punica_lock(punica);

    if (devices_database_delete_by_uuid(punica->rest_devices, uuid) != 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        devices_database_entry_free(device);
        punica_unlock(punica);
        return U_CALLBACK_COMPLETE;
    }

    linked_list_add(punica->rest_devices, device);

    devices_database_to_file(punica->rest_devices,
                             punica->settings->coap.database_file);

    punica_unlock(punica);

    ulfius_set_empty_body_response(u_response, HTTP_201_CREATED);
    return U_CALLBACK_COMPLETE;
}

int rest_devices_delete_cb(const struct _u_request *u_request,
                           struct _u_response *u_response,
                           void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    const char *uuid;

    punica_lock(punica);

    uuid = u_map_get(u_request->map_url, "uuid");
    if (uuid == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        punica_unlock(punica);

        return U_CALLBACK_COMPLETE;
    }

    if (devices_database_delete_by_uuid(punica->rest_devices, uuid) != 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        punica_unlock(punica);

        return U_CALLBACK_COMPLETE;
    }

    devices_database_to_file(punica->rest_devices,
                             punica->settings->coap.database_file);

    ulfius_set_empty_body_response(u_response, HTTP_204_NO_CONTENT);
    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}
