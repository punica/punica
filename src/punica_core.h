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

#ifndef PUNICA_H
#define PUNICA_H

#include <liblwm2m.h>
#include <ulfius.h>

#include "rest_core_types.h"
#include "settings.h"
#include "utils.h"

typedef struct
{
    pthread_mutex_t mutex;

    lwm2m_context_t *lwm2m;

    json_t *j_rest_callback;

    linked_list_t *rest_registrations;
    linked_list_t *rest_updates;
    linked_list_t *rest_deregistrations;
    linked_list_t *rest_timeouts;
    linked_list_t *rest_async_responses;
    linked_list_t *rest_pending_responses;
    linked_list_t *rest_observations;
    linked_list_t *rest_devices;

    settings_t *settings;
} punica_context_t;

void punica_initialize(punica_context_t *punica, settings_t *settings);
void punica_terminate(punica_context_t *punica);

void punica_lock(punica_context_t *punica);
void punica_unlock(punica_context_t *punica);

#endif // PUNICA_H
