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

#include "http_codes.h"
#include "punica.h"
#include "rest.h"
#include "rest_callbacks.h"

#include <string.h>

static json_t *endpoint_to_json(lwm2m_client_t *client)
{
    bool queue;

    switch (client->binding)
    {
    case BINDING_UQ:
    case BINDING_SQ:
    case BINDING_UQS:
        queue = true;
        break;
    default:
        queue = false;
        break;
    }

    json_t *j_client_description = json_object();
    json_object_set_new(j_client_description, "name", json_string(client->name));

    if (client->type != NULL)
    {
        json_object_set_new(j_client_description, "type", json_string(client->type));
    }

    json_object_set_new(j_client_description, "status", json_string("ACTIVE"));

    json_object_set_new(j_client_description, "q", json_boolean(queue));

    return j_client_description;
}

static json_t *endpoint_resources_to_json(lwm2m_client_t *client)
{
    lwm2m_client_object_t *obj;
    lwm2m_list_t *ins;
    char buf[20]; // 13 bytes should be enough (i.e. max string "/65535/65535\0")

    json_t *j_objects = json_array();
    for (obj = client->objectList; obj != NULL; obj = obj->next)
    {
        if (obj->instanceList == NULL)
        {
            snprintf(buf, sizeof(buf), "/%d", obj->id);
            json_t *j_object = json_object();
            json_object_set_new(j_object, "uri", json_string(buf));
            json_array_append_new(j_objects, j_object);
        }
        else
        {
            for (ins = obj->instanceList; ins != NULL; ins = ins->next)
            {
                snprintf(buf, sizeof(buf), "/%d/%d", obj->id, ins->id);
                json_t *j_object = json_object();
                json_object_set_new(j_object, "uri", json_string(buf));
                json_array_append_new(j_objects, j_object);
            }
        }
    }

    return j_objects;
}

int rest_endpoints_cb(const struct _u_request *u_request,
                      struct _u_response *u_response,
                      void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    lwm2m_client_t *client;

    punica_lock(punica);

    json_t *j_client_descriptions = json_array();
    for (client = punica->lwm2m->clientList; client != NULL; client = client->next)
    {
        json_array_append_new(j_client_descriptions, endpoint_to_json(client));
    }

    ulfius_set_json_body_response(u_response, HTTP_200_OK, j_client_descriptions);
    json_decref(j_client_descriptions);

    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_endpoints_name_cb(const struct _u_request *u_request,
                           struct _u_response *u_response,
                           void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    lwm2m_client_t *client;
    const char *name = u_map_get(u_request->map_url, "name");
    json_t *j_client_description;

    punica_lock(punica);

    client = utils_find_client(punica->lwm2m->clientList, name);

    if (client == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
    }
    else
    {
        j_client_description = endpoint_resources_to_json(client);
        ulfius_set_json_body_response(u_response, HTTP_200_OK, j_client_description);
        json_decref(j_client_description);
    }

    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

