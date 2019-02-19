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

#include <assert.h>
#include <string.h>

#include "database.h"
#include "logging.h"
#include "punica_core.h"

void punica_initialize(punica_core_t *punica, settings_t *settings)
{
    memset(punica, 0, sizeof(punica_core_t));
    punica->settings = settings;
    assert(pthread_mutex_init(&punica->mutex, NULL) == 0);

    punica->rest = malloc(sizeof(rest_core_t));
    rest_initialize(punica->rest);

    database_load_file(punica);
}

void punica_terminate(punica_core_t *punica)
{
    rest_terminate(punica->rest);
    free(punica->rest);
    assert(pthread_mutex_destroy(&punica->mutex) == 0);
}

void punica_lock(punica_core_t *punica)
{
    assert(pthread_mutex_lock(&punica->mutex) == 0);
}

void punica_unlock(punica_core_t *punica)
{
    assert(pthread_mutex_unlock(&punica->mutex) == 0);
}

lwm2m_client_t *lwm2m_endpoints_find_client(lwm2m_client_t *list, const char *name)
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
