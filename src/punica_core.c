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

#include "punica.h"
#include "devices_database.h"
#include "logging.h"
#include "settings.h"
#include "rest.h"

#include <assert.h>
#include <string.h>

void punica_initialize(punica_context_t *punica, settings_t *settings)
{
    punica->rest_registrations = linked_list_new();
    punica->rest_updates = linked_list_new();
    punica->rest_deregistrations = linked_list_new();
    punica->rest_timeouts = linked_list_new();
    punica->rest_async_responses = linked_list_new();
    punica->rest_pending_responses = linked_list_new();
    punica->rest_observations = linked_list_new();
    punica->settings = settings;
    punica->j_rest_callback = NULL;

    database_load_file(punica);

    assert(pthread_mutex_init(&punica->mutex, NULL) == 0);
}

void punica_terminate(punica_context_t *punica)
{
    if (punica->j_rest_callback)
    {
        json_decref(punica->j_rest_callback);
        punica->j_rest_callback = NULL;
    }

    rest_notifications_clear(punica);
    linked_list_delete(punica->rest_registrations);
    linked_list_delete(punica->rest_updates);
    linked_list_delete(punica->rest_deregistrations);
    linked_list_delete(punica->rest_timeouts);
    linked_list_delete(punica->rest_async_responses);
    linked_list_delete(punica->rest_pending_responses);
    linked_list_delete(punica->rest_observations);
    linked_list_delete(punica->rest_devices);

    assert(pthread_mutex_destroy(&punica->mutex) == 0);
}

void punica_lock(punica_context_t *punica)
{
    assert(pthread_mutex_lock(&punica->mutex) == 0);
}

void punica_unlock(punica_context_t *punica)
{
    assert(pthread_mutex_unlock(&punica->mutex) == 0);
}

