/*
 * Punica - LwM2M server with REST API
 * Copyright (C) 2019 8devices
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

#ifndef PUNICA_PLUGIN_MANAGER_REST_ULFIUS_REST_CORE_H
#define PUNICA_PLUGIN_MANAGER_REST_ULFIUS_REST_CORE_H

#include <punica/rest/core.h>

struct CUlfiusRestCore;
typedef struct CUlfiusRestCore CUlfiusRestCore;
CUlfiusRestCore *new_UlfiusRestCore(struct _u_instance *instance);
void delete_UlfiusRestCore(CUlfiusRestCore *c_core);
void UlfiusRestCore_startCore(CUlfiusRestCore *c_core);
void UlfiusRestCore_startSecureCore(
    CUlfiusRestCore *c_core, const char *c_private_key_file,
    const char *c_certificate_file);
void UlfiusRestCore_stopCore(CUlfiusRestCore *c_core);
void UlfiusRestCore_addHandler(
    CUlfiusRestCore *c_core,
    const char *method, const char *url_prefix,
    unsigned int priority, c_callback_function_t handler_function, void *handler_context);

#endif // PUNICA_PLUGIN_MANAGER_REST_ULFIUS_REST_CORE_H
