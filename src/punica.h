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

#include "rest_core_types.h"
#include "utils.h"
#include "settings.h"

#include <liblwm2m.h>
#include <ulfius.h>

typedef struct
{
    pthread_mutex_t mutex;

    lwm2m_context_t *lwm2m;

    // rest-core
    json_t *j_callback;

    // rest-notifications
    // linked_list_t *registrationList;
    linked_list_t *rest_registrations;
    // linked_list_t *updateList;
    linked_list_t *rest_updates;
    // linked_list_t *deregistrationList;
    linked_list_t *rest_deregistrations;
    // linked_list_t *timeoutList;
    linked_list_t *rest_timeouts;
    // linked_list_t *asyncResponseList;
    linked_list_t *rest_async_responses;

    // rest-resources
    // linked_list_t *pendingResponseList;
    linked_list_t *rest_pending_responses;

    // rest-subsciptions
    // linked_list_t *observeList;
    linked_list_t *rest_observations;

    // rest-devices
    // linked_list_t *devicesList;
    linked_list_t *rest_devices;

    settings_t *settings;
} punica_context_t;

void punica_init(punica_context_t *punica, settings_t *settings);
void punica_cleanup(punica_context_t *punica);

void punica_lock(punica_context_t *punica);
void punica_unlock(punica_context_t *punica);

#endif // PUNICA_H
