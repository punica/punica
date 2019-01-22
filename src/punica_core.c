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

#include "logging.h"
#include "punica.h"

#include <assert.h>
#include <string.h>

void punica_init(punica_context_t *punica, settings_t *settings)
{
    memset(punica, 0, sizeof(punica_context_t));

    punica->registrationList = linked_list_new();
    punica->updateList = linked_list_new();
    punica->deregistrationList = linked_list_new();
    punica->timeoutList = linked_list_new();
    punica->asyncResponseList = linked_list_new();
    punica->pendingResponseList = linked_list_new();
    punica->observeList = linked_list_new();
    punica->settings = settings;

    assert(pthread_mutex_init(&punica->mutex, NULL) == 0);
}

void punica_cleanup(punica_context_t *punica)
{
    if (punica->callback)
    {
        json_decref(punica->callback);
        punica->callback = NULL;
    }

    rest_notifications_clear(punica);
    linked_list_delete(punica->registrationList);
    linked_list_delete(punica->updateList);
    linked_list_delete(punica->deregistrationList);
    linked_list_delete(punica->timeoutList);
    linked_list_delete(punica->asyncResponseList);
    linked_list_delete(punica->pendingResponseList);
    linked_list_delete(punica->observeList);

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

