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

#ifndef PUNICA_CORE_H
#define PUNICA_CORE_H

#include <liblwm2m.h>
#include <ulfius.h>

#include "rest/rest-core-types.h"
#include "rest/rest-utils.h"
#include "rest/rest_core.h"
#include "settings.h"

typedef struct _u_request ulfius_req_t;
typedef struct _u_response ulfius_resp_t;

typedef struct
{
    pthread_mutex_t mutex;
    lwm2m_context_t *lwm2m;
    rest_core_t *rest;
    settings_t *settings;
} punica_core_t;

lwm2m_client_t *lwm2m_endpoints_find_client(lwm2m_client_t *list, const char *name);

void punica_initialize(punica_core_t *punica, settings_t *settings);
void punica_terminate(punica_core_t *punica);

void punica_lock(punica_core_t *punica);
void punica_unlock(punica_core_t *punica);

#endif // PUNICA_CORE_H

