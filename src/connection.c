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

#include "connection.h"
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rest-list.h"

typedef struct _connection_t
{
    struct _connection_t   *next;
    int                     sock;
    struct sockaddr_in6     addr;
    size_t                  addr_len;
} connection_t;

typedef struct connection_context_t
{
    connection_api_t api;
    rest_list_t *connection_list;
    int port;
    int address_family;
    int listen_socket;
} connection_context_t;

static int connection_start(void *context_p);
static int connection_close(void *context_p, void *connection);
static int connection_receive(void *context_p, uint8_t *buffer, size_t size, void **connection,
                              struct timeval *tv);
static int connection_send(void *context_p, void *connection, uint8_t *buffer, size_t length);
static int connection_stop(void *context_p);

static connection_t *connection_find(connection_context_t *context, struct sockaddr_storage *addr,
                                     size_t addr_len)
{
    connection_t *conn;
    rest_list_entry_t *conn_entry;

    for (conn_entry = context->connection_list->head; conn_entry != NULL; conn_entry = conn_entry->next)
    {
        conn = conn_entry->data;

        if ((conn->addr_len == addr_len) && (memcmp(&(conn->addr), addr, addr_len) == 0))
        {
            return conn;
        }
    }

    return NULL;
}

static connection_t *connection_new_incoming(connection_context_t *context, struct sockaddr *addr,
                                             size_t addr_len)
{
    connection_t *conn;

    conn = (connection_t *)malloc(sizeof(connection_t));
    if (conn != NULL)
    {
        conn->sock = context->listen_socket;
        memcpy(&(conn->addr), addr, addr_len);
        conn->addr_len = addr_len;

        rest_list_add(context->connection_list, conn);
    }

    return conn;
}

static int socket_receive(connection_context_t *context, uint8_t *buffer, size_t size,
                          void **connection)
{
    int ret;
    connection_t *conn;
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    ret = recvfrom(context->listen_socket, buffer, size, 0, (struct sockaddr *)&addr, &addr_len);

    if (ret < 0)
    {
        log_message(LOG_LEVEL_FATAL, "recvfrom() error: %d\n", ret);
        return -1;
    }

    conn = connection_find(context, &addr, addr_len);
    if (conn == NULL)
    {
        conn = connection_new_incoming(context, (struct sockaddr *)&addr, addr_len);
        if (conn == NULL)
        {
            return -1;
        }
    }

    *connection = conn;
    return ret;
}

int udp_connection_api_init(connection_api_t **conn_api, int port, int address_family)
{
    connection_context_t *context;
    context = calloc(1, sizeof(connection_context_t));
    if (context == NULL)
    {
        return -1;
    }

    context->port = port;
    context->address_family = address_family;

    context->api.f_start = connection_start;
    context->api.f_receive = connection_receive;
    context->api.f_send = connection_send;
    context->api.f_close = connection_close;
    context->api.f_stop = connection_stop;
    context->api.f_validate = NULL;
    *conn_api = &context->api;

    return 0;
}

static int connection_start(void *context_p)
{
    connection_context_t *context = (connection_context_t *)context_p;
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *p;
    char port_string[20];
    int sock = -1;

    sprintf(port_string, "%d", context->port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = context->address_family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if (0 != getaddrinfo(NULL, port_string, &hints, &res))
    {
        return -1;
    }

    for (p = res ; p != NULL && sock == -1 ; p = p->ai_next)
    {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock >= 0)
        {
            if (-1 == bind(sock, p->ai_addr, p->ai_addrlen))
            {
                close(sock);
                sock = -1;
            }
        }
    }

    context->connection_list = rest_list_new();
    if (context->connection_list == NULL)
    {
        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    context->listen_socket = sock;

    return sock;
}

static int connection_close(void *context_p, void *connection)
{
    connection_context_t *context = (connection_context_t *)context_p;
    connection_t *conn = (connection_t *)connection;

    if (conn == NULL)
    {
        return 0;
    }

    rest_list_remove(context->connection_list, conn);

    free(conn);
    return 0;
}

static int connection_send(void *context_p, void *connection, uint8_t *buffer, size_t length)
{
    connection_t *conn = (connection_t *)connection;
    int nbSent;
    size_t offset;

    offset = 0;
    while (offset != length)
    {
        nbSent = sendto(conn->sock, buffer + offset, length - offset, 0,
                        (struct sockaddr *) & (conn->addr), conn->addr_len);
        if (nbSent == -1) { return -1; }
        offset += nbSent;
    }
    return 0;
}

static int connection_receive(void *context_p, uint8_t *buffer, size_t size, void **connection,
                              struct timeval *tv)
{
    connection_context_t *context = (connection_context_t *)context_p;
    int res;
    fd_set readfds;

    FD_ZERO(&readfds);
    FD_SET(context->listen_socket, &readfds);

    res = select(context->listen_socket + 1, &readfds, NULL, NULL, tv);
    if (res < 0)
    {
        return res;
    }

    if (FD_ISSET(context->listen_socket, &readfds))
    {
        return socket_receive(context, buffer, size, connection);
    }

    return 0;
}

static int connection_stop(void *context_p)
{
    connection_context_t *context = (connection_context_t *)context_p;
    connection_t *conn;
    rest_list_entry_t *conn_entry;

    for (conn_entry = context->connection_list->head; conn_entry != NULL; conn_entry = conn_entry->next)
    {
        conn = conn_entry->data;

        connection_close(context, conn);
    }

    close(context->listen_socket);
    free(context);

    return 0;
}
