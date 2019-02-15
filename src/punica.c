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

#include "punica.h"
#include "rest.h"
#include "utils.h"
#include "linked_list.h"
#include "connection.h"
#include "logging.h"
#include "security.h"
#include "settings.h"
#include "rest_authentication.h"
#include "rest_callbacks.h"

#include <liblwm2m.h>

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

static char *logging_section = "";
static volatile int punica_quit;
static void sigint_handler(int signo)
{
    punica_quit = 1;
}

/**
 * Function called if we get a SIGPIPE. Does counting.
 * exmp. killall -13  punica
 * @param signal will be SIGPIPE (ignored)
 */
static void sigpipe_handler(int signal)
{
    static volatile int sigpipe_cnt;
    sigpipe_cnt++;

    logging_section = "[SIGNAL]";
    log_message(LOG_LEVEL_ERROR,
                "%s SIGPIPE occurs: %d times.\n", logging_section, sigpipe_cnt);
}

/**
 * initialize handlers for SIGINT, SIGPIPE and SIGTERM.
 */
static void signals_initialize(void)
{
    struct sigaction old_signal, signal;

    logging_section = "[SIGNAL]";
    // signal(SIGINT, sigint_handler); //automaticaly do SA_RESTART, we must break system functions exmp. select
    memset(&signal, 0, sizeof(signal));
    signal.sa_handler = &sigint_handler;
    sigemptyset(&signal.sa_mask);
    signal.sa_flags = 0; // break system functions open, read ... if SIGINT occurs
    if (0 != sigaction(SIGINT, &signal, &old_signal))
    {
        log_message(LOG_LEVEL_FATAL,
                    "%s Failed to install SIGINT handler: %s\n",
                    logging_section, strerror(errno));
    }

    //to stop valgrind
    if (0 != sigaction(SIGTERM, &signal, &old_signal))
    {
        log_message(LOG_LEVEL_FATAL,
                    "%s Failed to install SIGTERM handler: %s\n",
                    logging_section, strerror(errno));
    }

    memset(&signal, 0, sizeof(signal));
    signal.sa_handler = &sigpipe_handler;
    sigemptyset(&signal.sa_mask);
    signal.sa_flags = SA_RESTART;
    if (0 != sigaction(SIGPIPE, &signal, &old_signal))
    {
        log_message(LOG_LEVEL_FATAL,
                    "Failed to install SIGPIPE handler: %s\n",
                    logging_section, strerror(errno));
    }
}

void client_monitor_cb(uint16_t l_client_id, lwm2m_uri_t *l_uri_path,
                       int status, lwm2m_media_type_t l_format,
                       uint8_t *data, int dataLength,
                       void *userData)
{
    punica_context_t *punica = (punica_context_t *)userData;
    rest_notif_registration_t *registration_notification;
    rest_notif_deregistration_t *deregistration_notification;
    lwm2m_context_t *lwm2m = punica->lwm2m;;
    lwm2m_client_t *l_client;
    lwm2m_client_object_t *l_object;
    lwm2m_list_t *l_object_instance;

    logging_section = "[LwM2M]";

    l_client = (lwm2m_client_t *) lwm2m_list_find(
                   (lwm2m_list_t *)lwm2m->clientList, l_client_id);

    switch (status)
    {
    case COAP_201_CREATED:
    case COAP_204_CHANGED:
        if (status == COAP_201_CREATED)
        {
            registration_notification = rest_notif_registration_new();

            if (registration_notification != NULL)
            {
                rest_notif_registration_set(registration_notification,
                                            l_client->name);
                rest_notify_registration(punica, registration_notification);
            }
            else
            {
                log_message(LOG_LEVEL_ERROR,
                            "%s Failed to allocate registration notification!\n",
                            logging_section);
            }

            log_message(LOG_LEVEL_INFO, "%s Client %d registered.\n",
                        logging_section, l_client_id);
        }
        else
        {
            rest_notif_update_t *update_notification = rest_notif_update_new();

            if (update_notification != NULL)
            {
                rest_notif_update_set(update_notification, l_client->name);
                rest_notify_update(punica, update_notification);
            }
            else
            {
                log_message(LOG_LEVEL_ERROR,
                            "%s Failed to allocate update notification!\n",
                            logging_section);
            }

            log_message(LOG_LEVEL_INFO, "%s Client %d updated.\n",
                        logging_section, l_client_id);
        }

        log_message(LOG_LEVEL_DEBUG,
                    "\tname: \"%s\"\n\tbind: \"%s\"\n\tlifetime: %d\n\tobjects: ",
                    l_client->name, binding_to_string(l_client->binding),
                    l_client->lifetime);

        for (l_object = l_client->objectList;
             l_object != NULL; l_object = l_object->next)
        {
            if (l_object->instanceList == NULL)
            {
                log_message(LOG_LEVEL_DEBUG, "/%d, ", l_object->id);
            }
            else
            {
                for (l_object_instance = l_object->instanceList;
                     l_object_instance != NULL;
                     l_object_instance = l_object_instance->next)
                {
                    log_message(LOG_LEVEL_DEBUG, "/%d/%d, ",
                                l_object->id, l_object_instance->id);
                }
            }
        }
        log_message(LOG_LEVEL_DEBUG, "\n");
        break;

    case COAP_202_DELETED:
    {
        deregistration_notification = rest_notif_deregistration_new();

        if (deregistration_notification != NULL)
        {
            rest_notif_deregistration_set(deregistration_notification,
                                          l_client->name);
            rest_notify_deregistration(punica, deregistration_notification);
        }
        else
        {
            log_message(LOG_LEVEL_ERROR,
                        "%s Failed to allocate deregistration notification!\n",
                        logging_section);
        }

        log_message(LOG_LEVEL_INFO,
                    "%s Client %d deregistered.\n", logging_section, l_client_id);
        break;
    }
    default:
        log_message(LOG_LEVEL_INFO,
                    "%s Client %d status update %d.\n",
                    logging_section, l_client_id, status);
        break;
    }
}

int socket_receive(lwm2m_context_t *lwm2m, int coap_socket)
{
    int buffer_length;
    uint8_t buffer[1500];
    struct sockaddr_storage socket_address;
    socklen_t socket_address_size = sizeof(socket_address);
    connection_t *connection;
    static connection_t *connections = NULL;

    memset(buffer, 0, sizeof(buffer));

    buffer_length = recvfrom(coap_socket, buffer, sizeof(buffer),
                             0, (struct sockaddr *)&socket_address, &socket_address_size);

    if (buffer_length < 0)
    {
        log_message(LOG_LEVEL_ERROR,
                    "%s Failed to receive coap packet!\n", logging_section);

        log_message(LOG_LEVEL_DEBUG,
                    "%s recvfrom() returned error code: \"%d\"\n",
                    logging_section, buffer_length);
        return -1;
    }

    connection = connection_find(connections,
                                 &socket_address, socket_address_size);

    if (connection == NULL)
    {
        connection = connection_new_incoming(connections, coap_socket,
                                             (struct sockaddr *)&socket_address, socket_address_size);

        if (connection)
        {
            connections = connection;
        }
    }

    if (connection != NULL)
    {
        lwm2m_handle_packet(lwm2m, buffer, buffer_length, connection);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    punica_context_t punica;
    static settings_t settings;
    fd_set read_fds;
    char coap_port[6];
    int status_code, coap_socket;
    static struct _u_instance u_instance;
    static struct timeval tv_timeout_interval =
    {
        .tv_sec = 5,
        .tv_usec = 0,
    };

    logging_section = "[SETTINGS]";
    if (settings_initialize(&settings) != 0)
    {
        log_message(LOG_LEVEL_FATAL,
                    "%s Failed to initialize settings!\n", logging_section);
        return -1;
    }
    logging_initialize(&settings.logging);

    if (settings_load(&settings, argc, argv) != 0)
    {
        log_message(LOG_LEVEL_FATAL,
                    "%s Failed to load settings!\n", logging_section);
        return -1;
    }
    logging_initialize(&settings.logging);

    signals_initialize();

    punica_initialize(&punica, &settings);

    logging_section = "[LwM2M]";
    snprintf(coap_port, sizeof(coap_port), "%d", settings.coap.port);
    log_message(LOG_LEVEL_INFO,
                "%s Creating CoAP socket on port %s...\n",
                logging_section, coap_port);
    coap_socket = create_socket(coap_port, AF_INET6);
    if (coap_socket < 0)
    {
        log_message(LOG_LEVEL_FATAL,
                    "%s Failed to create socket!\n", logging_section);
        return -1;
    }

    punica.lwm2m = lwm2m_init(NULL);
    if (punica.lwm2m == NULL)
    {
        log_message(LOG_LEVEL_FATAL,
                    "%s Failed to initialize server instance!\n", logging_section);
        return -1;
    }

    lwm2m_set_monitoring_callback(punica.lwm2m, client_monitor_cb, &punica);

    logging_section = "[REST API]";
    log_message(LOG_LEVEL_INFO,
                "%s Creating HTTP socket on port %u...\n",
                logging_section, settings.http.port);
    if (ulfius_init_instance(&u_instance, settings.http.port,
                             NULL, NULL) != U_OK)
    {
        log_message(LOG_LEVEL_FATAL,
                    "%s Failed to initialize server instance!\n", logging_section);
        return -1;
    }

    /*
     * mbed Device Connector based api
     * https://docs.mbed.com/docs/mbed-device-connector-web-interfaces/en/latest/api-reference/
     */

    // Endpoints
    ulfius_add_endpoint_by_val(&u_instance,
                               "GET", "/endpoints", NULL, 10, &rest_endpoints_cb, &punica);
    ulfius_add_endpoint_by_val(&u_instance,
                               "GET", "/endpoints", ":name", 10, &rest_endpoints_name_cb, &punica);

    // Devices
    ulfius_add_endpoint_by_val(&u_instance, "GET", "/devices", NULL, 10,
                               &rest_devices_get_cb, &punica);
    ulfius_add_endpoint_by_val(&u_instance, "GET", "/devices", ":id", 10,
                               &rest_devices_get_name_cb, &punica);
    ulfius_add_endpoint_by_val(&u_instance, "PUT", "/devices", ":id", 10,
                               &rest_devices_put_cb, &punica);
    ulfius_add_endpoint_by_val(&u_instance, "POST", "/devices", NULL, 10,
                               &rest_devices_post_cb, &punica);
    ulfius_add_endpoint_by_val(&u_instance, "DELETE", "/devices", ":id", 10,
                               &rest_devices_delete_cb, &punica);

    // Resources
    ulfius_add_endpoint_by_val(&u_instance,
                               "*", "/endpoints", ":name/*", 10, &rest_resources_rwe_cb, &punica);

    // Notifications
    ulfius_add_endpoint_by_val(&u_instance,
                               "GET", "/notification/callback", NULL, 10,
                               &rest_notifications_get_callback_cb, &punica);
    ulfius_add_endpoint_by_val(&u_instance,
                               "PUT", "/notification/callback", NULL, 10,
                               &rest_notifications_put_callback_cb, &punica);
    ulfius_add_endpoint_by_val(&u_instance,
                               "DELETE", "/notification/callback", NULL, 10,
                               &rest_notifications_delete_callback_cb, &punica);
    ulfius_add_endpoint_by_val(&u_instance,
                               "GET", "/notification/pull", NULL, 10,
                               &rest_notifications_pull_cb, &punica);

    // Subscriptions
    ulfius_add_endpoint_by_val(&u_instance,
                               "PUT", "/subscriptions", ":name/*", 10,
                               &rest_subscriptions_put_cb, &punica);
    ulfius_add_endpoint_by_val(&u_instance,
                               "DELETE", "/subscriptions", ":name/*", 10,
                               &rest_subscriptions_delete_cb, &punica);

    // Version
    ulfius_add_endpoint_by_val(&u_instance,
                               "GET", "/version", NULL, 1, &rest_version_cb, NULL);

    // JWT authentication
    ulfius_add_endpoint_by_val(&u_instance,
                               "POST", "/authenticate", NULL, 1, &rest_authenticate_cb,
                               (void *)&settings.http.security.jwt);
    ulfius_add_endpoint_by_val(&u_instance,
                               "*", "*", NULL, 3, &rest_validate_jwt_cb,
                               (void *)&settings.http.security.jwt);

    if (settings.http.security.private_key != NULL
        || settings.http.security.certificate != NULL)
    {
        if (security_load(&(settings.http.security)) != 0)
        {
            log_message(LOG_LEVEL_FATAL,
                        "%s Failed to load server security!\n", logging_section);
            return -1;
        }

        if (ulfius_start_secure_framework(&u_instance,
                                          settings.http.security.private_key_file,
                                          settings.http.security.certificate_file) != U_OK)
        {
            log_message(LOG_LEVEL_FATAL,
                        "%s Failed to start secure server!\n", logging_section);
            return -1;
        }

        if (!settings.http.security.jwt.initialized)
        {
            log_message(LOG_LEVEL_WARN,
                        "%s Encryption without authentication is unadvisable!\n",
                        logging_section);
        }
    }
    else
    {
        if (ulfius_start_framework(&u_instance) != U_OK)
        {
            log_message(LOG_LEVEL_FATAL,
                        "%s Failed to start server!\n", logging_section);
            return -1;
        }

        if (settings.http.security.jwt.initialized)
        {
            log_message(LOG_LEVEL_WARN,
                        "%s Authentication without encryption is unadvisable!\n",
                        logging_section);
        }
    }

    if (settings.http.security.jwt.initialized)
    {
        if (settings.http.security.jwt.users_list->head == NULL)
        {
            log_message(LOG_LEVEL_WARN,
                        "%s JWT is initialized, but users list is empty!\n",
                        logging_section);
        }
        if (settings.http.security.jwt.secret_key == NULL)
        {
            log_message(LOG_LEVEL_WARN,
                        "%s JWT is initialized, but secret key is unavailable!\n",
                        logging_section);
        }
    }

    /* Main section */
    while (!punica_quit)
    {
        FD_ZERO(&read_fds);
        FD_SET(coap_socket, &read_fds);

        punica_lock(&punica);
        status_code = lwm2m_step(punica.lwm2m, &tv_timeout_interval.tv_sec);
        if (status_code)
        {
            logging_section = "[LwM2M]";
            log_message(LOG_LEVEL_ERROR,
                        "%s Failed to perform pending operations!\n",
                        logging_section);
            log_message(LOG_LEVEL_DEBUG,
                        "%s lwm2m_step() error: \"%d\".\n",
                        logging_section, status_code);
        }

        status_code = rest_step(&punica, &tv_timeout_interval);
        if (status_code)
        {
            logging_section = "[REST API]";
            log_message(LOG_LEVEL_ERROR,
                        "%s Failed to perform pending operations!\n",
                        logging_section);
            log_message(LOG_LEVEL_DEBUG,
                        "%s rest_step() error: %d\n",
                        logging_section, status_code);
        }
        punica_unlock(&punica);

        status_code = select(
                          FD_SETSIZE, &read_fds, NULL, NULL, &tv_timeout_interval);
        if (status_code < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            log_message(LOG_LEVEL_ERROR,
                        "%s Failed to read\n", logging_section);
            log_message(LOG_LEVEL_DEBUG,
                        "%s select() error: %d\n", logging_section, status_code);
        }

        if (FD_ISSET(coap_socket, &read_fds))
        {
            punica_lock(&punica);
            socket_receive(punica.lwm2m, coap_socket);
            punica_unlock(&punica);
        }

    }

    ulfius_stop_framework(&u_instance);
    ulfius_clean_instance(&u_instance);

    lwm2m_close(punica.lwm2m);
    punica_terminate(&punica);

    jwt_terminate(&settings.http.security.jwt);

    return 0;
}
