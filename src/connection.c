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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <liblwm2m.h>
#include "connection.h"
#include "logging.h"

static int sock = -1;

static connection_t * connection_find(connection_t * connList,
                               struct sockaddr_storage * addr,
                               size_t addrLen)
{
    connection_t * connP;

    connP = connList;
    while (connP != NULL)
    {
        if ((connP->addrLen == addrLen)
         && (memcmp(&(connP->addr), addr, addrLen) == 0))
        {
            return connP;
        }
        connP = connP->next;
    }

    return connP;
}

static connection_t * connection_new_incoming(connection_t * connList,
                                       struct sockaddr * addr,
                                       size_t addrLen)
{
    connection_t * connP;

    connP = (connection_t *)malloc(sizeof(connection_t));
    if (connP != NULL)
    {
        connP->sock = sock;
        memcpy(&(connP->addr), addr, addrLen);
        connP->addrLen = addrLen;
        connP->next = connList;
    }

    return connP;
}

static int socket_receive(void *ctx)
{
    int nbytes;
    uint8_t buf[1500];
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof(addr);
    connection_t *con;
    static connection_t *connectionList = NULL;

    memset(buf, 0, sizeof(buf));

    nbytes = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrLen);

    if (nbytes < 0)
    {
        log_message(LOG_LEVEL_FATAL, "recvfrom() error: %d\n", nbytes);
        return -1;
    }

    con = connection_find(connectionList, &addr, addrLen);
    if (con == NULL)
    {
        con = connection_new_incoming(connectionList, (struct sockaddr *)&addr, addrLen);
        if (con)
        {
            connectionList = con;
        }
    }

    if (con)
    {
        lwm2m_handle_packet(ctx, buf, nbytes, con);
    }

    return 0;
}

int connection_create(settings_t *options, int addressFamily)
{
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *p;

    char portStr[20];
    sprintf(portStr, "%d", options->coap.port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = addressFamily;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if (0 != getaddrinfo(NULL, portStr, &hints, &res))
    {
        return -1;
    }

    for(p = res ; p != NULL && sock == -1 ; p = p->ai_next)
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

    return sock;
}

//  TODO: free single device
void connection_free(void * connP)
{
    connection_t *connList = (connection_t *)connP;

    while (connList != NULL)
    {
        connection_t * nextP;

        nextP = connList->next;
        free(connList);

        connList = nextP;
    }
}

static int connection_send(connection_t *connP,
                    uint8_t * buffer,
                    size_t length)
{
    int nbSent;
    size_t offset;

#ifdef WITH_LOGS
    char s[INET6_ADDRSTRLEN];
    in_port_t port;

    s[0] = 0;

    if (AF_INET == connP->addr.sin6_family)
    {
        struct sockaddr_in *saddr = (struct sockaddr_in *)&connP->addr;
        inet_ntop(saddr->sin_family, &saddr->sin_addr, s, INET6_ADDRSTRLEN);
        port = saddr->sin_port;
    }
    else if (AF_INET6 == connP->addr.sin6_family)
    {
        struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)&connP->addr;
        inet_ntop(saddr->sin6_family, &saddr->sin6_addr, s, INET6_ADDRSTRLEN);
        port = saddr->sin6_port;
    }

    fprintf(stderr, "Sending %lu bytes to [%s]:%hu\r\n", length, s, ntohs(port));
#endif

    offset = 0;
    while (offset != length)
    {
        nbSent = sendto(connP->sock, buffer + offset, length - offset, 0, (struct sockaddr *)&(connP->addr), connP->addrLen);
        if (nbSent == -1) return -1;
        offset += nbSent;
    }
    return 0;
}

int connection_step(void *ctx, struct timeval *tv)
{
    int res;
    fd_set readfds;

    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);

//  TODO: should change FD_SETSIZE to a calculated value for optimization
    res = select(FD_SETSIZE, &readfds, NULL, NULL, tv);
    if (res < 0)
    {
        if (errno != EINTR)
        {
            return res;
        }
    }

    if (FD_ISSET(sock, &readfds))
    {
//      rest_lock() already locked before calling connection_step()
        return socket_receive(ctx);
    }

    return 0;
}

uint8_t lwm2m_buffer_send(void * sessionH,
                          uint8_t * buffer,
                          size_t length,
                          void * userdata)
{
    connection_t * connP = (connection_t*) sessionH;

    if (connP == NULL)
    {
        fprintf(stderr, "#> failed sending %lu bytes, missing connection\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }

    if (-1 == connection_send(connP, buffer, length))
    {
        fprintf(stderr, "#> failed sending %lu bytes\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }

    return COAP_NO_ERROR;
}

bool lwm2m_session_is_equal(void * session1,
                            void * session2,
                            void * userData)
{
    return (session1 == session2);
}
