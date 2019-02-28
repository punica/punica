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

#include "../punica.h"

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

    json_t *jclient = json_object();
    json_object_set_new(jclient, "name", json_string(client->name));

    if (client->type != NULL)
    {
        json_object_set_new(jclient, "type", json_string(client->type));
    }

    json_object_set_new(jclient, "status", json_string("ACTIVE"));

    json_object_set_new(jclient, "q", json_boolean(queue));

    return jclient;
}

static json_t *endpoint_resources_to_json(lwm2m_client_t *client)
{
    lwm2m_client_object_t *obj;
    lwm2m_list_t *ins;
    char buf[20]; // 13 bytes should be enough (i.e. max string "/65535/65535\0")

    json_t *jobjects = json_array();
    for (obj = client->objectList; obj != NULL; obj = obj->next)
    {
        if (obj->instanceList == NULL)
        {
            snprintf(buf, sizeof(buf), "/%d", obj->id);
            json_t *jobject = json_object();
            json_object_set_new(jobject, "uri", json_string(buf));
            json_array_append_new(jobjects, jobject);
        }
        else
        {
            for (ins = obj->instanceList; ins != NULL; ins = ins->next)
            {
                snprintf(buf, sizeof(buf), "/%d/%d", obj->id, ins->id);
                json_t *jobject = json_object();
                json_object_set_new(jobject, "uri", json_string(buf));
                json_array_append_new(jobjects, jobject);
            }
        }
    }

    return jobjects;
}

lwm2m_client_t *rest_endpoints_find_client(lwm2m_client_t *list, const char *name)
{
    lwm2m_client_t *client;

    if (name == NULL)
    {
        return NULL;
    }

    for (client = list; client != NULL; client = client->next)
    {
        if (strcmp(client->name, name) == 0)
        {
            return client;
        }
    }

    return NULL;
}

int rest_endpoints_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    lwm2m_client_t *client;

    rest_lock(rest);

    json_t *jclients = json_array();
    for (client = rest->lwm2m->clientList; client != NULL; client = client->next)
    {
        json_array_append_new(jclients, endpoint_to_json(client));
    }

    ulfius_set_json_body_response(resp, 200, jclients);
    json_decref(jclients);

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_endpoints_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    lwm2m_client_t *client;
    const char *name = u_map_get(req->map_url, "name");
    json_t *jclient;

    rest_lock(rest);

    client = rest_endpoints_find_client(rest->lwm2m->clientList, name);

    if (client == NULL)
    {
        ulfius_set_empty_body_response(resp, 404);
    }
    else
    {
        jclient = endpoint_resources_to_json(client);
        ulfius_set_json_body_response(resp, 200, jclient);
        json_decref(jclient);
    }

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

