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

#include "rest_core_types.h"
#include "utils.h"

#include <liblwm2m.h>

#include <stdio.h>
#include <string.h>

rest_async_response_t *rest_async_response_new(void)
{
    rest_async_response_t *response;

    response = malloc(sizeof(rest_async_response_t));
    if (response == NULL)
    {
        return NULL;
    }
    memset(response, 0, sizeof(rest_async_response_t));

    if (utils_generate_async_response_id(response->id) != 0)
    {
        return NULL;
    }

    return response;
}

rest_async_response_t *rest_async_response_clone(
    const rest_async_response_t *response)
{
    rest_async_response_t *clone;

    clone = rest_async_response_new();
    if (clone == NULL)
    {
        return NULL;
    }

    // XXX: should the payload be cloned?
    memcpy(clone->id, response->id, sizeof(clone->id));

    return clone;
}

void rest_async_response_delete(rest_async_response_t *response)
{
    if (response->payload != NULL)
    {
        free((void *)response->payload);
    }

    free(response);
}

int rest_async_response_set(rest_async_response_t *response, int status,
                            const uint8_t *payload, size_t length)
{
    response->timestamp = lwm2m_getmillis();
    response->status = status;

    if (response->payload != NULL)
    {
        free((void *)response->payload);
        response->payload = NULL;
    }

    size_t base64_length;
    if (base64_encode(payload, length, NULL, &base64_length))
    {
        return -1;
    }

    response->payload = (const char *)calloc(1, base64_length + 1);
    if (response->payload == NULL)
    {
        return -1;
    }

    if (base64_encode(payload, length, (char *)response->payload,
                      &base64_length))
    {
        return -1;
    }

    return 0;
}

rest_notif_registration_t *rest_notif_registration_new(void)
{
    rest_notif_registration_t *registration;

    registration = malloc(sizeof(rest_notif_registration_t));
    if (registration == NULL)
    {
        return NULL;
    }

    memset(registration, 0, sizeof(rest_notif_registration_t));

    return registration;
}

void rest_notif_registration_delete(rest_notif_registration_t *registration)
{
    if (registration->name)
    {
        free((void *)registration->name);
        registration->name = NULL;
    }

    free(registration);
}

int rest_notif_registration_set(rest_notif_registration_t *registration,
                                const char *name)
{
    if (registration->name)
    {
        free((void *)registration->name);
        registration->name = NULL;
    }

    if (name != NULL)
    {
        registration->name = strdup(name);
        if (registration->name == NULL)
        {
            return -1;
        }
    }

    return 0;
}

rest_notif_update_t *rest_notif_update_new(void)
{
    rest_notif_update_t *update;

    update = malloc(sizeof(rest_notif_update_t));
    if (update == NULL)
    {
        return NULL;
    }

    memset(update, 0, sizeof(rest_notif_update_t));

    return update;
}

void rest_notif_update_delete(rest_notif_update_t *update)
{
    if (update->name)
    {
        free((void *)update->name);
        update->name = NULL;
    }

    free(update);
}

int rest_notif_update_set(rest_notif_update_t *update, const char *name)
{
    if (update->name)
    {
        free((void *)update->name);
        update->name = NULL;
    }

    if (name != NULL)
    {
        update->name = strdup(name);
        if (update->name == NULL)
        {
            return -1;
        }
    }

    return 0;
}

rest_notif_deregistration_t *rest_notif_deregistration_new(void)
{
    rest_notif_deregistration_t *deregistration;

    deregistration = malloc(sizeof(rest_notif_deregistration_t));
    if (deregistration == NULL)
    {
        return NULL;
    }

    memset(deregistration, 0, sizeof(rest_notif_deregistration_t));

    return deregistration;
}

void rest_notif_deregistration_delete(
    rest_notif_deregistration_t *deregistration)
{
    if (deregistration->name)
    {
        free((void *)deregistration->name);
        deregistration->name = NULL;
    }

    free(deregistration);
}

int rest_notif_deregistration_set(
    rest_notif_deregistration_t *deregistration, const char *name)
{
    if (deregistration->name)
    {
        free((void *)deregistration->name);
        deregistration->name = NULL;
    }

    if (name != NULL)
    {
        deregistration->name = strdup(name);
        if (deregistration->name == NULL)
        {
            return -1;
        }
    }

    return 0;
}

