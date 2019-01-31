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

#include "rest-list.h"

#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>


rest_list_t *rest_list_new(void)
{
    rest_list_t *list = malloc(sizeof(rest_list_t));

    if (list == NULL)
    {
        return NULL;
    }

    memset(list, 0, sizeof(rest_list_t));

    pthread_mutex_init(&list->mutex, NULL);
    list->head = NULL;

    return list;
}

void rest_list_delete(rest_list_t *list)
{
    rest_list_entry_t *entry;
    rest_list_entry_t *next;

    pthread_mutex_lock(&list->mutex);

    entry = list->head;
    while (entry != NULL)
    {
        next = entry->next;
        free(entry);
        entry = next;
    }

    pthread_mutex_unlock(&list->mutex);

    pthread_mutex_destroy(&list->mutex);

    free(list);
}

void rest_list_add(rest_list_t *list, void *data)
{
    rest_list_entry_t *entry;

    pthread_mutex_lock(&list->mutex);

    entry = malloc(sizeof(rest_list_entry_t));
    assert(entry != NULL);

    entry->next = list->head;
    entry->data = data;
    list->head = entry;

    pthread_mutex_unlock(&list->mutex);
}

void rest_list_remove(rest_list_t *list, void *data)
{
    pthread_mutex_lock(&list->mutex);

    rest_list_entry_t *entry, *previous;

    for (entry = list->head; entry != NULL; entry = entry->next)
    {
        if (entry->data == data)
        {
            if (entry == list->head)
            {
                list->head = entry->next;
                entry->next = NULL;
                free(entry);
            }
            else
            {
                previous->next = entry->next;
                entry->next = NULL;
                free(entry);
            }

            pthread_mutex_unlock(&list->mutex);
            return;
        }

        previous = entry;
    }

    assert(false);
}

void rest_list_append(rest_list_t *list, rest_list_t *extension)
{
    rest_list_entry_t *entry;

    pthread_mutex_lock(&list->mutex);

    if (list->head == NULL)
    {
        list->head = extension->head;
        goto exit;
    }

    for (entry = list->head; entry->next != NULL; entry = entry->next)
    {
    }
    entry->next = extension->head;

exit:
    pthread_mutex_destroy(&extension->mutex);
    free(extension);

    pthread_mutex_unlock(&list->mutex);
}
