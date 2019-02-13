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

static int connection_timeout_secure(gnutls_transport_ptr_t context, unsigned int ms);

static int prv_new_socket(const char *host, const char *port, int address_family)
{
    //TODO fix returns
    int ret, sock;
    struct addrinfo hints, *addr_list, *cur;

//    if( ( ret = net_prepare() ) != 0 )
//        return( ret );

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = address_family;
    hints.ai_socktype = SOCK_DGRAM;
    //hints.ai_protocol = IPPROTO_UDP;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG;

    if (host == NULL)
        hints.ai_flags |= AI_PASSIVE;

    if (getaddrinfo(host, port, &hints, &addr_list) != 0)
        return MBEDTLS_ERR_NET_UNKNOWN_HOST;

    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    for (cur = addr_list; cur != NULL; cur = cur->ai_next)
    {
        sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (sock < 0)
        {
            ret = MBEDTLS_ERR_NET_SOCKET_FAILED;
            continue;
        }

        if (bind(sock, cur->ai_addr, cur->ai_addrlen))
        {
            close( sock );
            ret = MBEDTLS_ERR_NET_BIND_FAILED;
            continue;
        }

        ret = 0;
        break;
    }

    freeaddrinfo(addr_list);
    return sock;
}

int connection_create_secure(settings_t *options, int address_family, void *psk_context)
{
    char port_str[20];
//  TODO: should check if already globally initialized
//    gnutls_global_init();

    if (options->coap.certificate_file)
    {
        gnutls_certificate_allocate_credentials(&server_cert);
        gnutls_certificate_set_x509_trust_file(server_cert, options->coap.certificate_file, GNUTLS_X509_FMT_PEM);
        
        CHECK_RET(gnutls_certificate_set_x509_key_file(server_cert, options->coap.certificate_file, options->coap.private_key_file, GNUTLS_X509_FMT_PEM));
    }

//    gnutls_certificate_set_known_gh_params(server_cert, GNUTLS_SEC_PARAM_MEDIUM);

    CHECK_RET(gnutls_priority_init(&priority_cache, "NORMAL:+VERS-DTLS1.2:+AES-128-CCM-8:+PSK", NULL));

    gnutls_key_generate(&cookie_key, GNUTLS_COOKIE_KEY_SIZE);

    gnutls_psk_allocate_server_credentials(&server_psk);
    gnutls_psk_set_server_credentials_function(server_psk, psk_callback);

    sprintf(port_str, "%d", options->coap.port);
    listen_fd = prv_new_socket(NULL, port_str, address_family);
//      {
//          getaddrinfo
//          socket
//          sockopt
//          bind
//      }
//    listen_fd = socket(address_family, SOCK_DGRAM, 0);
//    mbedtls_net_bind
    return 0;
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

static device_connection_t *connection_new_incoming(int sock)
{
    int ret;
    char buffer[BUFF_SIZE];
    gnutls_dtls_prestate_st prestate;
    device_connection_t *connP;

    connP = (device_connection_t *)malloc(sizeof(device_connection_t));
    if (connP == NULL)
    {
        return NULL;
    }
    connP->sock = sock;

hello_verify:
    connP->addr_size = sizeof(connP->addr);
    // is MSG_PEEK needed?
    ret = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&connP->addr, &connP->addr_size);
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &connP->addr.sin_addr, str, INET_ADDRSTRLEN);
        printf("%s addr: %s\r\n", __func__, str);
    //ret = recvfrom(sock, buffer, sizeof(buffer), MSG_PEEK, (struct sockaddr *)&client_addr, &client_addr_size);
    if (ret > 0)
    {
        memset(&prestate, 0, sizeof(prestate));

//      check if cookie is valid, if not send hello verify
        ret = gnutls_dtls_cookie_verify(&cookie_key, &connP->addr, sizeof(connP->addr), buffer, ret, &prestate);
        if (ret < 0)
        {
            gnutls_dtls_cookie_send(&cookie_key, &connP->addr, sizeof(connP->addr), &prestate, connP, connection_send_secure);
            //try verify again once
            goto hello_verify;
        }
        else
        {
            //init and so on
            //create new socket for connection
            gnutls_init(&connP->session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
//          might be used later
//            CHECK_RET(gnutls_credentials_set());
            gnutls_priority_set(connP->session, priority_cache);
            gnutls_dtls_prestate_set(connP->session, &prestate);
//            gnutls_dtls_set_mtu(connP->session, );

            gnutls_transport_set_ptr(connP->session, connP);
            gnutls_transport_set_push_function(connP->session, connection_send_secure);
            gnutls_transport_set_pull_function(connP->session, connection_receive_secure);
            gnutls_transport_set_pull_timeout_function(connP->session, connection_timeout_secure);

            do {
                ret = gnutls_handshake(connP->session);
            } while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);

            if (ret < 0)
            {
//              handshake failure
//              deinit session
//              free connP
//              return NULL;
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
    else if (ret == 0)
    {
//      keep this in case we want to manage ret < 0 error
        return ret;
    }

    connP_curr = connection_list;
    while (connP_curr != NULL)
    {
        if (FD_ISSET(connP_curr->sock, &read_fds))
        {
//            ret = mbedtls_ssl_read(connP_curr->ssl, buf, opt.buffer_size - 1);
            if (ret > 0)
            {
                lwm2m_handle_packet(context, buffer, ret, connP_curr);
            }
        }
        connP_curr = connP_curr->next;
    }

    if (FD_ISSET(listen_fd, &read_fds))
    {
        device_connection_t *connP = connection_new_incoming(listen_fd);
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

ssize_t connection_send_secure(gnutls_transport_ptr_t context, const void *data, size_t size)
//int connection_send_secure(void *sessionH, uint8_t *buffer, size_t length)
{
    int ret;
    device_connection_t *connP = (device_connection_t *)context;

    inet_pton(AF_INET, "127.0.0.1", &connP->addr.sin_addr);
    //return mbedtls_ssl_write(connP->ssl, buffer, length);
    ret = sendto(connP->sock, data, size, 0, (struct sockaddr *)&connP->addr, connP->addr_size);
    if (errno)
    {
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &connP->addr.sin_addr, str, INET_ADDRSTRLEN);
        printf("addr: %s\r\n", str);
        char s[50];
        sprintf(s, "ret = %d: ", ret);
        perror(s);
    }
    return ret;
}

ssize_t connection_receive_secure(gnutls_transport_ptr_t context, void *data, size_t size)
{
    device_connection_t *connP = (device_connection_t *)context;

    connP->addr_size = sizeof(connP->addr);
    return recvfrom(connP->sock, data, size, 0, (struct sockaddr *)&connP->addr, &connP->addr_size);
}

static int connection_timeout_secure(gnutls_transport_ptr_t context, unsigned int ms)
{
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
        return ret;

    connP->addr_size = sizeof(connP->addr);

    ret = recvfrom(connP->sock, dummy_buff, sizeof(dummy_buff), MSG_PEEK, (struct sockaddr *)&connP->addr, &connP->addr_size);
    if (ret > 0)
    {
        return 1;
    }

    return 0;
}
