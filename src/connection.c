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
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <liblwm2m.h>
#include "logging.h"

typedef struct connection_context_t
{
    connection_api_t api;
    connection_t *connection_list;
    int port;
    int address_family;
    int listen_socket;
} connection_context_t;

static connection_t *connection_find(void *this, struct sockaddr_storage *addr, size_t addr_len)
{
    connection_context_t *context = (connection_context_t *)this;
    connection_t *conn_curr;

    conn_curr = context->connection_list;
    while (conn_curr != NULL)
    {
        if ((conn_curr->addr_len == addr_len) && (memcmp(&(conn_curr->addr), addr, addr_len) == 0))
        {
            return conn_curr;
        }
        conn_curr = conn_curr->next;
    }

    return NULL;
}

static connection_t *connection_new_incoming(void *this, struct sockaddr *addr, size_t addr_len)
{
    connection_context_t *context = (connection_context_t *)this;
    connection_t *conn;

    conn = (connection_t *)malloc(sizeof(connection_t));
    if (conn != NULL)
    {
        conn->sock = context->listen_socket;
        memcpy(&(conn->addr), addr, addr_len);
        conn->addr_len = addr_len;
        conn->next = context->connection_list;
    }

    return conn;
}

static int socket_receive(void *this, uint8_t *buffer, size_t size, void **connection)
{
    connection_context_t *context = (connection_context_t *)this;
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

    conn = connection_find(this, &addr, addr_len);
    if (conn == NULL)
    {
        conn = connection_new_incoming(this, (struct sockaddr *)&addr, addr_len);
        if (conn)
        {
            context->connection_list = conn;
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
    *conn_api = &context->api;

    return 0;
}

int connection_start(void *this)
{
    connection_context_t *context = (connection_context_t *)this;
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

    freeaddrinfo(res);
    context->listen_socket = sock;

    return sock;
}

int connection_close(void *this, void *connection)
{
    connection_context_t *context = (connection_context_t *)this;
    connection_t *conn = (connection_t *)connection;
    connection_t *conn_curr = context->connection_list;
    connection_t *next;

    if (conn_curr == NULL)
    {
        return 0;
    }
    else if (conn == conn_curr)
    {
        next = conn_curr->next;
        free(conn);
        context->connection_list = next;
        return 0;
    }

    while (conn_curr->next != conn)
    {
        conn_curr = conn_curr->next;
    }

    conn_curr->next = conn->next;
    free(conn);
    return 0;
}

int connection_send(void *this, void *connection, uint8_t *buffer, size_t length)
{
    connection_t *conn = (connection_t *)connection;
    int nbSent;
    size_t offset;

#ifdef WITH_LOGS
    char s[INET6_ADDRSTRLEN];
    in_port_t port;

    s[0] = 0;

    if (AF_INET == conn->addr.sin6_family)
    {
        struct sockaddr_in *saddr = (struct sockaddr_in *)&conn->addr;
        inet_ntop(saddr->sin_family, &saddr->sin_addr, s, INET6_ADDRSTRLEN);
        port = saddr->sin_port;
    }
    else if (AF_INET6 == conn->addr.sin6_family)
    {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&conn->addr;
        inet_ntop(saddr->sin6_family, &saddr->sin6_addr, s, INET6_ADDRSTRLEN);
        port = saddr->sin6_port;
    }

    fprintf(stderr, "Sending %lu bytes to [%s]:%hu\r\n", length, s, ntohs(port));
#endif

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

int connection_receive(void *this, uint8_t *buffer, size_t size, void **connection,
                       struct timeval *tv)
{
    connection_context_t *context = (connection_context_t *)this;
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
        return socket_receive(this, buffer, size, connection);
    }

    return 0;
}

int connection_stop(void *this)
{
    connection_context_t *context = (connection_context_t *)this;
    connection_t *curr, *next;

    curr = context->connection_list;
    while (curr != NULL)
    {
        next = curr->next;
        connection_close(this, curr);
        curr = next;
    }

    close(context->listen_socket);
    free(context);

    return 0;
}
