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

#include <stdio.h>

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#include "connection-secure.h"

#define BUFFER_SIZE 1024

static gnutls_certificate_credentials_t server_cert = NULL;
static gnutls_priority_t priority_cache = NULL;
static gnutls_datum_t cookie_key;
static gnutls_psk_server_credentials_t server_psk = NULL;

static int listen_socket;
static device_connection_t *connection_list = NULL;

static ssize_t prv_net_send(gnutls_transport_ptr_t context, const void *data, size_t size)
{
    device_connection_t *conn = (device_connection_t *)context;

    return sendto(conn->sock, data, size, 0, (struct sockaddr *)&conn->addr, conn->addr_size);
}

static int prv_new_socket(const char *host, int port, int address_family)
{
    int sock, enable;
    struct addrinfo hints, *addr_list, *cur;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = address_family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_ADDRCONFIG;

    if (host == NULL)
    {
        hints.ai_flags |= AI_PASSIVE;
    }

    sprintf(port_str, "%d", port);
    if (getaddrinfo(host, port_str, &hints, &addr_list) != 0)
    {
        return -1;
    }

    for (cur = addr_list; cur != NULL; cur = cur->ai_next)
    {
        sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (sock < 0)
        {
            continue;
        }

        enable = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable)))
        {
            close(sock);
            sock = -1;
            continue;
        }

        if (bind(sock, cur->ai_addr, cur->ai_addrlen))
        {
            close(sock);
            sock = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(addr_list);
    return sock;
}

static int prv_switch_sockets(int *local_socket, int *client_socket,
                              struct sockaddr_storage *client_address, socklen_t address_length)
{
    socklen_t size;
    struct sockaddr_storage local_address;
    char service[16];
    int port;

    if (connect(*local_socket, (struct sockaddr *)client_address, sizeof(struct sockaddr_storage)))
    {
        return -1;
    }

    *client_socket = *local_socket;

    size = sizeof(struct sockaddr_storage);
    if (getsockname(*client_socket, (struct sockaddr *)&local_address, &size))
    {
        return -1;
    }

    if (getnameinfo((struct sockaddr *)&local_address, size, NULL, 0, service, sizeof(service),
                    NI_NUMERICSERV))
    {
        return -1;
    }
    port = atoi(service);

    *local_socket = prv_new_socket(NULL, port, local_address.ss_family);

    return 0;
}

static int prv_cookie_negotiate(device_connection_t *connection, gnutls_dtls_prestate_st *prestate)
{
    int ret;
    char buffer[BUFFER_SIZE];

    for (int i = 0; i < 2; i++)
    {
        connection->addr_size = sizeof(connection->addr);

        ret = recvfrom(connection->sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&connection->addr,
                       &connection->addr_size);
        if (ret > 0)
        {
            memset(prestate, 0, sizeof(gnutls_dtls_prestate_st));

            ret = gnutls_dtls_cookie_verify(&cookie_key, &connection->addr, sizeof(connection->addr), buffer,
                                            ret, prestate);
            if (ret == 0)
            {
                return 0;
            }
            else
            {
                gnutls_dtls_cookie_send(&cookie_key, &connection->addr, sizeof(connection->addr), prestate,
                                        connection, prv_net_send);
            }
        }
        else
        {
            return -1;
        }
    }

    return -1;
}

static int prv_connection_init(device_connection_t *connection, gnutls_dtls_prestate_st *prestate)
{
    int ret = -1;

    if (gnutls_init(&connection->session, GNUTLS_SERVER | GNUTLS_DATAGRAM))
    {
        goto exit;
    }
    if (gnutls_credentials_set(connection->session, GNUTLS_CRD_PSK, server_psk))
    {
        goto exit;
    }
    if (gnutls_credentials_set(connection->session, GNUTLS_CRD_CERTIFICATE, server_cert))
    {
        goto exit;
    }
    if (gnutls_priority_set(connection->session, priority_cache))
    {
        goto exit;
    }

    gnutls_dtls_prestate_set(connection->session, prestate);
    gnutls_transport_set_ptr(connection->session, (void *)((intptr_t)connection->sock));

    ret = 0;
exit:
    if (ret)
    {
        gnutls_deinit(connection->session);
    }
    return ret;
}

int connection_create_secure(settings_t *options, int address_family, void *context)
{
    int ret = -1;

    if (gnutls_global_init())
    {
        goto exit;
    }

    if (options->coap.certificate_file)
    {
        if (gnutls_certificate_allocate_credentials(&server_cert) != GNUTLS_E_SUCCESS)
        {
            goto exit;
        }
        if (gnutls_certificate_set_x509_trust_file(server_cert, options->coap.certificate_file,
                                                   GNUTLS_X509_FMT_PEM) == 0)
        {
            goto exit;
        }
        if (gnutls_certificate_set_x509_key_file(server_cert, options->coap.certificate_file,
                                                 options->coap.private_key_file, GNUTLS_X509_FMT_PEM))
        {
            goto exit;
        }
    }

    if (gnutls_priority_init(&priority_cache, "NORMAL:+VERS-DTLS1.2:+AES-128-CCM-8:+PSK:+ECDHE-ECDSA",
                             NULL) != GNUTLS_E_SUCCESS)
    {
        goto exit;
    }
    if (gnutls_key_generate(&cookie_key, GNUTLS_COOKIE_KEY_SIZE) != GNUTLS_E_SUCCESS)
    {
        goto exit;
    }
    if (gnutls_psk_allocate_server_credentials(&server_psk) != GNUTLS_E_SUCCESS)
    {
        goto exit;
    }

    gnutls_psk_set_server_credentials_function(server_psk, psk_callback);
    set_psk_callback_context(context);

    listen_socket = prv_new_socket(NULL, options->coap.port, address_family);
    ret = listen_socket;

exit:
    if (ret <= 0)
    {
        gnutls_certificate_free_credentials(server_cert);
        gnutls_priority_deinit(priority_cache);
        gnutls_psk_free_server_credentials(server_psk);
    }
    return ret;
}

static device_connection_t *connection_new_incoming(int *sock)
{
    int ret, port;
    char service[16];
    const char *err_str;
    gnutls_dtls_prestate_st prestate;
    device_connection_t *conn;

    conn = (device_connection_t *)malloc(sizeof(device_connection_t));
    if (conn == NULL)
    {
        return NULL;
    }
    conn->sock = *sock;

    if (prv_cookie_negotiate(conn, &prestate) == 0)
    {
//      the current socket will be taken over by the client connection and a new one created for listening for incoming connections
        if (prv_switch_sockets(sock, &conn->sock, &conn->addr, conn->addr_size))
        {
            getnameinfo((struct sockaddr *)&conn->addr, conn->addr_size, NULL, 0, service, sizeof(service),
                        NI_NUMERICSERV);
            port = atoi(service);

            *sock = prv_new_socket(NULL, port, conn->addr.ss_family);

            close(conn->sock);
            free(conn);
            return NULL;
        }

        if (prv_connection_init(conn, &prestate))
        {
            close(conn->sock);
            free(conn);
            return NULL;
        }

        do
        {
            ret = gnutls_handshake(conn->session);
        } while (ret == GNUTLS_E_AGAIN);

        if (ret < 0)
        {
            err_str = gnutls_strerror(ret);
            log_message(LOG_LEVEL_WARN, "Handshake failed with message: '%s'\n", err_str);

            gnutls_deinit(conn->session);
            close(conn->sock);
            free(conn);
            return NULL;
        }
    }
    else
    {
        free(conn);
        return NULL;
    }

    return conn;
}

int connection_step_secure(void *context, struct timeval *tv)
{
    uint8_t buffer[BUFFER_SIZE];
    int ret, nfds = 0;
    fd_set read_fds;
    device_connection_t *conn_curr = connection_list;

    FD_ZERO(&read_fds);

    while (conn_curr != NULL)
    {
        FD_SET(conn_curr->sock, &read_fds);
        if (conn_curr->sock >= nfds)
        {
            nfds = conn_curr->sock + 1;
        }
        conn_curr = conn_curr->next;
    }

    FD_SET(listen_socket, &read_fds);
    if (listen_socket >= nfds)
    {
        nfds = listen_socket + 1;
    }

    ret = select(nfds, &read_fds, NULL, NULL, tv);
    if (ret <= 0)
    {
        return ret;
    }

    conn_curr = connection_list;
    while (conn_curr != NULL)
    {
        if (FD_ISSET(conn_curr->sock, &read_fds))
        {
            conn_curr->addr_size = sizeof(conn_curr->addr);
            ret = recvfrom(conn_curr->sock, buffer, sizeof(buffer), MSG_PEEK,
                           (struct sockaddr *)&conn_curr->addr, &conn_curr->addr_size);
            ret = gnutls_record_recv(conn_curr->session, buffer, ret);
            if (ret > 0)
            {
                lwm2m_handle_packet(context, buffer, ret, conn_curr);
            }
        }
        conn_curr = conn_curr->next;
    }

    if (FD_ISSET(listen_socket, &read_fds))
    {
        device_connection_t *conn_new = connection_new_incoming(&listen_socket);
        if (conn_new == NULL)
        {
            log_message(LOG_LEVEL_WARN, "Failed to connect to device\n");
            return -1;
        }

        conn_new->next = connection_list;
        connection_list = conn_new;
    }

    return 0;
}

int connection_free_secure(void *connection)
{
    device_connection_t *conn = (device_connection_t *)connection;
    int ret;

    if (connection_list == NULL)
    {
        return 0;
    }

    if (conn == connection_list)
    {
        connection_list = conn->next;
        goto free;
    }

    device_connection_t *conn_curr = connection_list;
    do
    {
        if (conn_curr->next == conn)
        {
            conn_curr->next = conn->next;
            goto free;
        }
        conn_curr = conn_curr->next;
    } while (conn_curr->next != NULL);

free:
    do
    {
        ret = gnutls_bye(conn->session, GNUTLS_SHUT_RDWR);
    } while (ret == GNUTLS_E_AGAIN);

    if (ret != GNUTLS_E_SUCCESS)
    {
        return -1;
    }

    gnutls_deinit(conn->session);
    close(conn->sock);
    free(conn);
    return 0;
}

int connection_send_secure(void *connection, uint8_t *buffer, size_t length)
{
    device_connection_t *conn = (device_connection_t *)connection;

    return gnutls_record_send(conn->session, buffer, length);
}