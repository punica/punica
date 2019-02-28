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

#include "settings.h"
#include "rest-core-types.h"
#include "rest-list.h"
#include "restserver.h"

int database_load_file(rest_context_t *rest)
{
    json_error_t error;
    size_t index;
    json_t *j_entry;
    json_t *j_database = NULL;
    int ret = 1;
    database_entry_t *curr;

    linked_list_t *device_list = linked_list_new();
    if (device_list == 0)
    {
        fprintf(stderr, "%s:%d - failed to allocate device list\r\n",
                __FILE__, __LINE__);
        goto exit;
    }

    rest->devicesList = device_list;
    if (rest->settings->coap.database_file == NULL)
    {
//      internal list created, nothing more to do here
        ret = 0;
        goto exit;
    }

    j_database = json_load_file(rest->settings->coap.database_file, 0, &error);
    if (j_database == NULL)
    {
        fprintf(stdout, "%s:%d - database file not found, must be created with /devices REST API\r\n",
                __FILE__, __LINE__);
        ret = 0;
        goto exit;
    }

    if (!json_is_array(j_database))
    {
        fprintf(stderr, "%s:%d - database file must contain a json array\r\n",
                __FILE__, __LINE__);
        linked_list_delete(device_list);
        goto exit;
    }

    int array_size = json_array_size(j_database);
    if (array_size == 0)
    {
//      empty array, must be populated with /devices REST API
        ret = 0;
        goto exit;
    }

    json_array_foreach(j_database, index, j_entry)
    {
        if (database_validate_entry(j_entry))
        {
            fprintf(stdout, "Found error(s) in device entry no. %ld\n", index);
            continue;
        }

        curr = calloc(1, sizeof(database_entry_t));
        if (curr == NULL)
        {
            goto exit;
        }

        if (database_populate_entry(j_entry, curr))
        {
            fprintf(stdout, "Internal server error while managing device entry\n");
            goto free_device;
        }

        linked_list_add(device_list, (void *)curr);
        continue;

free_device:
        database_free_entry(curr);
    }
    ret = 0;

exit:
    json_decref(j_database);
    return ret;
}
