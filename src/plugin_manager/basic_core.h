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

#ifndef PUNICA_PLUGIN_MANAGER_BASIC_CORE_H
#define PUNICA_PLUGIN_MANAGER_BASIC_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <liblwm2m.h>
#include <ulfius.h>

struct basic_punica_core_t;
typedef struct basic_punica_core_t basic_punica_core_t;

basic_punica_core_t *basic_punica_core_new(struct _u_instance *ulfius_instance,
                                           lwm2m_context_t *lwm2m_context);
void basic_punica_core_delete(basic_punica_core_t *core);

#ifdef __cplusplus
}
#endif

#endif // PUNICA_PLUGIN_MANAGER_BASIC_CORE_H
