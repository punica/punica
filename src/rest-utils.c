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

#include "rest-utils.h"

#include "restserver.h"


int coap_to_http_status(int status)
{
    switch (status)
    {
    case COAP_204_CHANGED:
    case COAP_205_CONTENT:
        return HTTP_200_OK;

    case COAP_404_NOT_FOUND:
        return HTTP_404_NOT_FOUND;

    default:
        return -(((status >> 5) & 0x7) * 100 + (status & 0x1F));
    }
}

void free_device_list(device_database_t *head)
{
    device_database_t *curr, *next;
    curr = head;

    while(curr != NULL)
    {
        next = curr->next;
        if(curr->uuid)
        {
            free(curr->uuid);
        }
        if(curr->psk)
        {
            free(curr->psk);
        }
        if(curr->psk_id)
        {
            free(curr->psk_id);
        }
        free(curr);
        curr = next;
    }
}

device_database_t * alloc_device_list(size_t size)
{
    if(size < 1)
    {
        return NULL;
    }
    device_database_t *head, *next = NULL;

    for(int i = 0; i < size; i++)
    {
        head = calloc(1, sizeof(device_database_t));
        if(head == NULL)
        {
            free_device_list(next);
            return NULL;
        }
        head->next = next;
        next = head;
    }

    return head;
}

int remove_device_list(device_database_t **list, const char* id)
{
    if(*list == NULL || id == NULL)
    {
        return -1;
    }

    device_database_t *prev = NULL, *curr;
    curr = *list;

    while(curr != NULL)
    {
        if(strcmp(id, curr->uuid) == 0)
        {
            if(curr == *list)
            {
                *list = curr->next;
                return 0;
            }
            prev->next = curr->next;
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }

    return -1;
}
