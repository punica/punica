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

#ifndef REST_H
#define REST_H

#include <time.h>

#include <jansson.h>

#include "punica.h"
#include "rest_core_types.h"

void rest_notify_registration(
    punica_context_t *punica,
    rest_notif_registration_t *reg);
void rest_notify_update(
    punica_context_t *punica,
    rest_notif_update_t *update);
void rest_notify_deregistration(
    punica_context_t *punica,
    rest_notif_deregistration_t *dereg);
void rest_notify_timeout(
    punica_context_t *punica,
    rest_notif_timeout_t *timeout);
void rest_notify_async_response(
    punica_context_t *punica,
    rest_notif_async_response_t *u_response);

json_t *rest_notifications_json(punica_context_t *punica);
void rest_notifications_clear(punica_context_t *punica);

int rest_initialize(punica_context_t *punica, http_settings_t *settings);
int rest_setup_callbacks(punica_context_t *punica);
int rest_terminate(punica_context_t *punica);

int rest_step(punica_context_t *punica, struct timeval *tv);

#endif // REST_H
