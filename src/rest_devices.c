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
#include "linked_list.h"
#include "http_codes.h"
#include "punica.h"
#include "settings.h"

#include <string.h>

static int rest_devices_update_list(linked_list_t *list, json_t *j_device)
{
    const char *string;
    json_t *j_string;
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;
    uint8_t *oldpsk, *oldid;
    uint8_t binary_buffer[512];
    size_t length;

    j_string = json_object_get(j_device, "uuid");
    string = json_string_value(j_string);

    for (device_entry = list->head;
         device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(device_data->uuid, string) == 0)
        {
            j_string = json_object_get(j_device, "psk");
            string = json_string_value(j_string);

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

            j_string = json_object_get(j_device, "psk_id");
            string = json_string_value(j_string);

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

static int rest_devices_remove_list(linked_list_t *list, const char *id)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;

    for (device_entry = list->head;
         device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(id, device_data->uuid) == 0)
        {
            linked_list_remove(list, (void *)device_data);
            return 0;
        }
    }

    return -1;
}

static json_t *rest_devices_prepare_resp(database_entry_t *device_entry)
{
    json_t *j_resp_obj;
    char psk_id_buf[512];
    size_t length = sizeof(psk_id_buf);

    if (base64_encode(device_entry->psk_id, device_entry->psk_id_len,
                      psk_id_buf, &length))
    {
        return NULL;
    }

    j_resp_obj = json_pack("{s:s, s:s}",
                           "uuid", device_entry->uuid,
                           "psk_id", psk_id_buf);
    if (j_resp_obj == NULL)
    {
        return NULL;
    }

    return j_resp_obj;
}

int rest_devices_get_cb(const struct _u_request *u_request,
                        struct _u_response *u_response, void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    linked_list_t *device_list = punica->rest_devices;
    database_entry_t *device_data;
    linked_list_entry_t *device_entry;
    json_t *j_devices = NULL;
    json_t *j_entry_object;

    punica_lock(punica);

    j_devices = json_array();
    for (device_entry = device_list->head;
         device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        j_entry_object = rest_devices_prepare_resp(device_data);
        if (j_entry_object == NULL)
        {
            ulfius_set_empty_body_response(u_response,
                                           HTTP_500_INTERNAL_ERROR);
            goto exit;
        }

        json_array_append_new(j_devices, j_entry_object);
    }

    ulfius_set_json_body_response(u_response, HTTP_200_OK, j_devices);

exit:
    json_decref(j_devices);
    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_get_name_cb(const struct _u_request *u_request,
                             struct _u_response *u_response,
                             void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    linked_list_t *device_list = punica->rest_devices;
    database_entry_t *device_data;
    linked_list_entry_t *device_entry;
    json_t *j_entry_object = NULL;

    punica_lock(punica);

    const char *id;
    id = u_map_get(u_request->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        goto exit;
    }

    for (device_entry = device_list->head;
         device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;
        if (strcmp(id, device_data->uuid) == 0)
        {
            j_entry_object = rest_devices_prepare_resp(device_data);
            if (j_entry_object == NULL)
            {
                ulfius_set_empty_body_response(u_response,
                                               HTTP_500_INTERNAL_ERROR);
                goto exit;
            }

            ulfius_set_json_body_response(u_response,
                                          HTTP_200_OK, j_entry_object);
            goto exit;
        }
    }

    ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);

exit:
    json_decref(j_entry_object);
    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_post_cb(const struct _u_request *u_request,
                         struct _u_response *u_response,
                         void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    const char *content_type;
    json_t *j_device = NULL, *j_database_list = NULL;
    json_t *j_post_resp;
    database_entry_t *device_entry;

    punica_lock(punica);

    content_type = u_map_get_case(u_request->map_header, "Content-Type");
    if (content_type == NULL
        || strcmp(content_type, "application/json") != 0)
    {
        ulfius_set_empty_body_response(u_response,
                                       HTTP_415_UNSUPPORTED_MEDIA_TYPE);
        goto exit;
    }

    j_device = json_loadb(u_request->binary_body,
                          u_request->binary_body_length, 0, NULL);
    if (devices_database_new_entry_validate(j_device))
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        goto exit;
    }

    device_entry = calloc(1, sizeof(database_entry_t));
    if (device_entry == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        goto exit;
    }

    if (devices_database_entry_new_from_json(j_device, device_entry))
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        goto exit;
    }
    linked_list_add(punica->rest_devices, device_entry);

    /* if database file not specified then only save locally */
    if (punica->settings->coap.database_file)
    {
        j_database_list = json_array();

        if (devices_database_to_json(punica->rest_devices, j_database_list) != 0)
        {
            ulfius_set_empty_body_response(u_response,
                                           HTTP_500_INTERNAL_ERROR);
            goto exit;
        }

        if (json_dump_file(j_database_list,
                           punica->settings->coap.database_file, 0) != 0)
        {
            ulfius_set_empty_body_response(u_response,
                                           HTTP_500_INTERNAL_ERROR);
            goto exit;
        }
    }

    j_post_resp = rest_devices_prepare_resp(device_entry);
    if (j_post_resp == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        goto exit;
    }

    ulfius_set_json_body_response(u_response, HTTP_201_CREATED, j_post_resp);

exit:
    json_decref(j_device);
    json_decref(j_database_list);
    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_put_cb(const struct _u_request *u_request,
                        struct _u_response *u_response, void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    json_t *j_device = NULL, *j_database_list = NULL, *j_string = NULL;
    const char *content_type, *id;

    punica_lock(punica);

    content_type = u_map_get_case(u_request->map_header, "Content-Type");
    if (content_type == NULL
        || strcmp(content_type, "application/json") != 0)
    {
        ulfius_set_empty_body_response(u_response,
                                       HTTP_415_UNSUPPORTED_MEDIA_TYPE);
        goto exit;
    }

    id = u_map_get(u_request->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        goto exit;
    }

    j_device = json_loadb(u_request->binary_body,
                          u_request->binary_body_length, 0, NULL);
    if (!json_is_object(j_device))
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        goto exit;
    }
    if (json_object_get(j_device, "psk") == NULL
        || json_object_get(j_device, "psk_id") == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        goto exit;
    }

    j_string = json_string(id);
    json_object_set_new(j_device, "uuid", j_string);

    /* if later stages fail, global list will be updated,
     *                       database file won't be updated.
     * TODO: consider updating list at the end */
    if (rest_devices_update_list(punica->rest_devices, j_device))
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        goto exit;
    }

    /* if database file does not exist then only save locally */
    if (punica->settings->coap.database_file == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_201_CREATED);
        goto exit;
    }

    j_database_list = json_array();

    if (devices_database_to_json(punica->rest_devices, j_database_list))
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        goto exit;
    }

    if (json_dump_file(j_database_list,
                       punica->settings->coap.database_file, 0) != 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        goto exit;
    }

    ulfius_set_empty_body_response(u_response, HTTP_201_CREATED);

exit:
    json_decref(j_device);
    json_decref(j_database_list);
    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_devices_delete_cb(const struct _u_request *u_request,
                           struct _u_response *u_response,
                           void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    json_t *j_database_list = NULL;

    punica_lock(punica);

    const char *id;
    id = u_map_get(u_request->map_url, "id");
    if (id == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        goto exit;
    }

    if (rest_devices_remove_list(punica->rest_devices, id) != 0)
    {
        /* device not found */
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        goto exit;
    }

    /* if database file not specified then only save locally */
    if (punica->settings->coap.database_file == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_200_OK);
        goto exit;
    }

    j_database_list = json_array();

    if (devices_database_to_json(punica->rest_devices, j_database_list))
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        goto exit;
    }

    if (json_dump_file(j_database_list,
                       punica->settings->coap.database_file, 0) != 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_500_INTERNAL_ERROR);
        goto exit;
    }

    ulfius_set_empty_body_response(u_response, HTTP_200_OK);

exit:
    json_decref(j_database_list);
    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}
