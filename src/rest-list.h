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

#ifndef REST_LIST_H
#define REST_LIST_H

#include <pthread.h>


typedef struct rest_list_entry_t
{
    struct rest_list_entry_t *next;
    void *data;
} rest_list_entry_t;

typedef struct
{
    pthread_mutex_t mutex;
    rest_list_entry_t *head;
} rest_list_t;

/**
 * This function creates new list resource.
 *
 * @return Pointer to a new list instance or NULL on error
 *
 */
rest_list_t *rest_list_new(void);

/**
 * This functions deletes list resource.
 *
 * @param[in]  list  Pointer to the list which will be delted
 *
 */
void rest_list_delete(rest_list_t *list);

/**
 * Adds data entry to the list.
 *
 * @param[in]  list  Pointer to the list
 * @param[in]  data  Data entry to be added
 */
void rest_list_add(rest_list_t *list, void *data);

/**
 * Removes data entry from the list. The data MUST be present in the list,
 * otherwise an assertion error occurs. If there are multiple data entries,
 * then only one of them is removed.
 *
 * @param[in]  list  Pointer to the list
 * @param[in]  data  Data entry to be removed
 */
void rest_list_remove(rest_list_t *list, void *data);

/**
 * This function joins two lists by appending. Appended list is cleared,
 * but its contents are moved to the first ones end.
 *
 * @param[in]  list           Pointer to the list
 * @param[in]  appended_list  Pointer to list to be appended
 */
void rest_list_append(rest_list_t *list, rest_list_t *appended_list);

#endif // REST_LIST_H
