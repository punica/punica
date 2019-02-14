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

//  TODO: camel-case code to something else (uniform)
#include <stdio.h>

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#include "connection-secure.h"

#define BUFF_SIZE 1024
//  TODO: extract function name from 'func'
#define CHECK_RET(func); \
    do {                 \
        if(func < 0)     \
        {                \
            fprintf(stderr, "%s returned error\n", #func); \
        }                \
    } while (0);         \

static gnutls_certificate_credentials_t server_cert;
static gnutls_priority_t priority_cache;
static gnutls_datum_t cookie_key;
static gnutls_psk_server_credentials_t server_psk;

static int listen_fd;
static device_connection_t *connection_list = NULL;

static ssize_t prv_net_send(gnutls_transport_ptr_t context, const void *data, size_t size)
{
    device_connection_t *connP = (device_connection_t *)context;

    return sendto(connP->sock, data, size, 0, (struct sockaddr *)&connP->addr, connP->addr_size);
}

static ssize_t prv_net_receive(gnutls_transport_ptr_t context, void *data, size_t size)
{
    device_connection_t *connP = (device_connection_t *)context;

    connP->addr_size = sizeof(connP->addr);
    return recvfrom(connP->sock, data, size, 0, (struct sockaddr *)&connP->addr, &connP->addr_size);
}

static int prv_net_receive_timeout(gnutls_transport_ptr_t context, unsigned int ms)
{
//  TODO: review
    device_connection_t *connP = (device_connection_t *)context;
    int ret;
    fd_set fds;
    struct timeval tv;
    char dummy_buff[1];

    FD_ZERO(&fds);
    FD_SET(connP->sock, &fds);

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    ret = select(connP->sock + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0)
    {
        return ret;
    }

    connP->addr_size = sizeof(connP->addr);
    ret = recvfrom(connP->sock, dummy_buff, sizeof(dummy_buff), MSG_PEEK,
                   (struct sockaddr *)&connP->addr, &connP->addr_size);
    if (ret > 0)
    {
        return 1;
    }

    return 0;
}

static int prv_new_socket(const char *host, int port, int address_family)
{
    int sock, enable;
    struct addrinfo hints, *addr_list, *cur;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
//  TODO: fails to write if family ipv6
//    hints.ai_family = address_family;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    //hints.ai_protocol = IPPROTO_UDP;
    hints.ai_protocol = 0;
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
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable));

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
                              struct sockaddr_in *client_address, socklen_t address_length)
{
    socklen_t size;
    struct sockaddr_in local_address;

    if (connect(*local_socket, (struct sockaddr *)client_address, sizeof(struct sockaddr_in)))
    {
        return -1;
    }

    *client_socket = *local_socket;

    size = sizeof(struct sockaddr_in);
    if (getsockname(*local_socket, (struct sockaddr *)&local_address, &size))
    {
        return -1;
    }

    *local_socket = prv_new_socket(NULL, ntohs(local_address.sin_port), local_address.sin_family);

    return *local_socket;
}

int connection_create_secure(settings_t *options, int address_family, void *context)
{
//  TODO: should check if already globally initialized
    CHECK_RET(gnutls_global_init());

    if (options->coap.certificate_file)
    {
        gnutls_certificate_allocate_credentials(&server_cert);
        gnutls_certificate_set_x509_trust_file(server_cert, options->coap.certificate_file,
                                               GNUTLS_X509_FMT_PEM);

        CHECK_RET(gnutls_certificate_set_x509_key_file(server_cert, options->coap.certificate_file,
                                                       options->coap.private_key_file, GNUTLS_X509_FMT_PEM));
    }

//    gnutls_certificate_set_known_gh_params(server_cert, GNUTLS_SEC_PARAM_MEDIUM);

//  TODO: should DTLS be only 1.2?
    CHECK_RET(gnutls_priority_init(&priority_cache,
                                   "NORMAL:+VERS-DTLS-ALL:+AES-128-CCM-8:+PSK:+ECDHE-ECDSA", NULL));

    gnutls_key_generate(&cookie_key, GNUTLS_COOKIE_KEY_SIZE);

    gnutls_psk_allocate_server_credentials(&server_psk);
    gnutls_psk_set_server_credentials_function(server_psk, psk_callback);
    set_psk_callback_context(context);

    listen_fd = prv_new_socket(NULL, options->coap.port, address_family);

    return listen_fd;
}

//static int prv_session_init(device_connection_t *connP)
//{
//    mbedtls_ssl_init(connP->ssl);
//#if defined(MBEDTLS_SSL_PROTO_DTLS)
//    if (opt.dgram_packing != DFL_DGRAM_PACKING)
//    {
//        mbedtls_ssl_set_datagram_packing(connP->ssl, opt.dgram_packing);
//    }
//#endif /* MBEDTLS_SSL_PROTO_DTLS */
//
//    mbedtls_ssl_set_bio(connP->ssl, connP->sock, mbedtls_net_send, mbedtls_net_recv,
//                        mbedtls_net_recv_timeout);
//
////    ret = mbedtls_ssl_setup(&connP->ssl, &conf);
//    mbedtls_ssl_setup(connP->ssl, &conf);
//
//#if defined(MBEDTLS_SSL_PROTO_DTLS)
//    if (opt.dtls_mtu != DFL_DTLS_MTU)
//    {
//        mbedtls_ssl_set_mtu(connP->ssl, opt.dtls_mtu);
//    }
//#endif
//#if defined(MBEDTLS_TIMING_C)
//    mbedtls_ssl_set_timer_cb(connP->ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
//#endif
//
//    mbedtls_ssl_session_reset(connP->ssl);
//
//    return 0;
//}

static device_connection_t *connection_new_incoming(int *sock)
{
    int ret;
    char buffer[BUFF_SIZE];
    const char *err_str;
    gnutls_dtls_prestate_st prestate;
    device_connection_t *connP;

    connP = (device_connection_t *)malloc(sizeof(device_connection_t));
    if (connP == NULL)
    {
        return NULL;
    }
    connP->sock = *sock;

//  TODO: prv_cookie_verify()
hello_verify:
    connP->addr_size = sizeof(connP->addr);
    ret = recvfrom(*sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&connP->addr,
                   &connP->addr_size);
    if (ret > 0)
    {
        memset(&prestate, 0, sizeof(prestate));

//      check if cookie is valid, if not send hello verify
        ret = gnutls_dtls_cookie_verify(&cookie_key, &connP->addr, sizeof(connP->addr), buffer, ret,
                                        &prestate);
        if (ret < 0)
        {
            gnutls_dtls_cookie_send(&cookie_key, &connP->addr, sizeof(connP->addr), &prestate, connP,
                                    prv_net_send);
//          TODO: try verify again once
            goto hello_verify;
        }
        else
        {
//          TODO: explain this function call
            CHECK_RET(prv_switch_sockets(sock, &connP->sock, &connP->addr, connP->addr_size));
            gnutls_init(&connP->session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
            CHECK_RET(gnutls_credentials_set(connP->session, GNUTLS_CRD_PSK, server_psk));
            CHECK_RET(gnutls_credentials_set(connP->session, GNUTLS_CRD_CERTIFICATE, server_cert));
            gnutls_priority_set(connP->session, priority_cache);
            gnutls_dtls_prestate_set(connP->session, &prestate);
//            gnutls_dtls_set_mtu(connP->session, );

            gnutls_transport_set_ptr(connP->session, connP);
//          TODO: might not be needed
            gnutls_transport_set_push_function(connP->session, prv_net_send);
            gnutls_transport_set_pull_function(connP->session, prv_net_receive);
            gnutls_transport_set_pull_timeout_function(connP->session, prv_net_receive_timeout);

            do
            {
                ret = gnutls_handshake(connP->session);
            } while (ret == GNUTLS_E_AGAIN);

            if (ret < 0)
            {
                err_str = gnutls_strerror(ret);
                log_message(LOG_LEVEL_WARN, "Handshake failed with message: '%s'\r\n", err_str);

                gnutls_deinit(connP->session);
                free(connP);
                return NULL;
            }

            connP->next = connection_list;
            connection_list = connP;
        }
    }
    else
    {
        free(connP);
        return NULL;
    }

    return connP;
}

int connection_step_secure(void *context, struct timeval *tv)
{
    uint8_t buffer[BUFF_SIZE];
    int ret, nfds = 0;
    fd_set read_fds;
    device_connection_t *connP_curr = connection_list;

    FD_ZERO(&read_fds);

    while (connP_curr != NULL)
    {
        FD_SET(connP_curr->sock, &read_fds);
        if (connP_curr->sock >= nfds)
        {
            nfds = connP_curr->sock + 1;
        }
        connP_curr = connP_curr->next;
    }

    FD_SET(listen_fd, &read_fds);
    if (listen_fd >= nfds)
    {
        nfds = listen_fd + 1;
    }

    ret = select(nfds, &read_fds, NULL, NULL, tv);
    if (ret < 0)
    {
//      errno
        return ret;
    }
    if (ret == 0)
    {
//      keep this in case we want to manage ret < 0 error
        return ret;
    }

    connP_curr = connection_list;
    while (connP_curr != NULL)
    {
        if (FD_ISSET(connP_curr->sock, &read_fds))
        {
//          TODO: something smarter
            connP_curr->addr_size = sizeof(connP_curr->addr);
            ret = recvfrom(connP_curr->sock, buffer, sizeof(buffer), MSG_PEEK,
                           (struct sockaddr *)&connP_curr->addr, &connP_curr->addr_size);
            ret = gnutls_record_recv(connP_curr->session, buffer, ret);
            if (ret > 0)
            {
                lwm2m_handle_packet(context, buffer, ret, connP_curr);
            }
        }
        connP_curr = connP_curr->next;
    }

    if (FD_ISSET(listen_fd, &read_fds))
    {
        device_connection_t *connP = connection_new_incoming(&listen_fd);
        if (connP == NULL)
        {
//          TODO: add error
            return -1;
        }
//        unsigned char client_ip[16] = { 0 };
//        size_t cliip_len;
//
//hello_verify:
//        mbedtls_net_accept(&listen_fd, connP->sock, client_ip, sizeof(client_ip), &cliip_len);
//        mbedtls_ssl_set_client_transport_id(connP->ssl, client_ip, cliip_len);
//
//        ret = mbedtls_ssl_read(connP->ssl, buf, opt.buffer_size - 1);
//        if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)
//        {
//            mbedtls_net_free(connP->sock);
//            mbedtls_ssl_session_reset(connP->ssl);
//            goto hello_verify;
//        }
//        else if (ret > 0)
//        {
//            lwm2m_handle_packet(context, buf, ret, connP);
//        }
//        else
//        {
//            connection_free_secure(connP);
//        }
    }

    return 0;
}

void connection_free_secure(void *connection)
{
//  gnutls_bye()
//  gnutls_deinit()

//    device_connection_t *connP = (device_connection_t *)connection;
//
//    if (connection_list == NULL)
//    {
//        return;
//    }
//
//    if (connP == connection_list)
//    {
//        connection_list = connP->next;
//        goto free;
//    }
//
//    device_connection_t *connP_curr = connection_list;
//
//    do
//    {
//        if (connP_curr->next == connP)
//        {
//            connP_curr->next = connP->next;
//            goto free;
//        }
//        connP_curr = connP_curr->next;
//    } while (connP_curr->next != NULL);
//
//free:
////  check if NULL to avoid double free?
//    mbedtls_ssl_close_notify(connP->ssl);
//    mbedtls_net_free(connP->sock);
//    free(connP->sock);
//    mbedtls_ssl_free(connP->ssl);
//    free(connP->ssl);
//    free(connP);
}

int connection_send_secure(void *session, uint8_t *buffer, size_t length)
{
    device_connection_t *connP = (device_connection_t *)session;

    return gnutls_record_send(connP->session, buffer, length);
}
