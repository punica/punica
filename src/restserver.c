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

#include <sys/socket.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>

#include <liblwm2m.h>
#include <ulfius.h>

#include "udp_connection_api.h"
#include "dtls_connection_api.h"
#include "restserver.h"
#include "logging.h"
#include "settings.h"
#include "version.h"
#include "security.h"
#include "rest-list.h"
#include "rest-authentication.h"

static volatile int restserver_quit;
static void sigint_handler(int signo)
{
    restserver_quit = 1;
}

/**
 * Function called if we get a SIGPIPE. Does counting.
 * exmp. killall -13  restserver
 * @param sig will be SIGPIPE (ignored)
 */
static void sigpipe_handler(int sig)
{
    static volatile int sigpipe_cnt;
    sigpipe_cnt++;
    log_message(LOG_LEVEL_ERROR, "SIGPIPE occurs: %d times.\n", sigpipe_cnt);
}


/**
 * setup handlers to ignore SIGPIPE, handle SIGINT...
 */
static void init_signals(void)
{
    struct sigaction oldsig;
    struct sigaction sig;

    //signal(SIGINT, sigint_handler);//automaticaly do SA_RESTART, we must break system functions exmp. select
    memset(&sig, 0, sizeof(sig));
    sig.sa_handler = &sigint_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;//break system functions open, read ... if SIGINT occurs
    if (0 != sigaction(SIGINT, &sig, &oldsig))
    {
        log_message(LOG_LEVEL_FATAL, "Failed to install SIGINT handler: %s\n", strerror(errno));
    }

    //to stop valgrind
    if (0 != sigaction(SIGTERM, &sig, &oldsig))
    {
        log_message(LOG_LEVEL_FATAL, "Failed to install SIGTERM handler: %s\n", strerror(errno));
    }


    memset(&sig, 0, sizeof(sig));
    sig.sa_handler = &sigpipe_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = SA_RESTART;
    if (0 != sigaction(SIGPIPE, &sig, &oldsig))
    {
        log_message(LOG_LEVEL_FATAL, "Failed to install SIGPIPE handler: %s\n", strerror(errno));
    }
}

static connection_api_t *api_init(coap_settings_t *coap, void *data, f_psk_cb_t psk_cb)
{
    if (coap->security_mode == PUNICA_COAP_MODE_INSECURE)
    {
        return udp_connection_api_init(coap->port, AF_INET6);
    }
    else if (coap->security_mode == PUNICA_COAP_MODE_SECURE)
    {
        return dtls_connection_api_init(coap->port, AF_INET6, coap->certificate_file,
                                        coap->private_key_file, data, psk_cb);
    }
    else
    {
        log_message(LOG_LEVEL_FATAL, "Found unsupported CoAP security mode: %d\n", coap->security_mode);
        return NULL;
    }
}

static void api_deinit(int security_mode, connection_api_t *api)
{
    if (security_mode == PUNICA_COAP_MODE_INSECURE)
    {
        udp_connection_api_deinit(api);
    }
    else if (security_mode == PUNICA_COAP_MODE_SECURE)
    {
        dtls_connection_api_deinit(api);
    }
}

const char *binding_to_string(lwm2m_binding_t bind)
{
    switch (bind)
    {
    case BINDING_U:
        return "U";
    case BINDING_UQ:
        return "UQ";
    case BINDING_S:
        return "S";
    case BINDING_SQ:
        return "SQ";
    case BINDING_US:
        return "US";
    case BINDING_UQS:
        return "UQS";
    default:
        return "Unknown";
    }
}


int rest_version_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    ulfius_set_string_body_response(resp, 200, PUNICA_VERSION);

    return U_CALLBACK_COMPLETE;
}

void client_monitor_cb(uint16_t clientID, lwm2m_uri_t *uriP, int status,
                       lwm2m_media_type_t format, uint8_t *data, int dataLength,
                       void *userData)
{
    rest_context_t *rest = (rest_context_t *)userData;
    lwm2m_context_t *lwm2m = rest->lwm2m;
    lwm2m_client_t *client;
    lwm2m_client_object_t *obj;
    lwm2m_list_t *ins;

    client = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)lwm2m->clientList, clientID);

    switch (status)
    {
    case COAP_201_CREATED:
    case COAP_204_CHANGED:
        if (status == COAP_201_CREATED)
        {
            rest_notif_registration_t *regNotif = rest_notif_registration_new();

            if (regNotif != NULL)
            {
                rest_notif_registration_set(regNotif, client->name);
                rest_notify_registration(rest, regNotif);
            }
            else
            {
                log_message(LOG_LEVEL_ERROR, "[MONITOR] Failed to allocate registration notification!\n");
            }

            log_message(LOG_LEVEL_INFO, "[MONITOR] Client %d registered.\n", clientID);
        }
        else
        {
            rest_notif_update_t *updateNotif = rest_notif_update_new();

            if (updateNotif != NULL)
            {
                rest_notif_update_set(updateNotif, client->name);
                rest_notify_update(rest, updateNotif);
            }
            else
            {
                log_message(LOG_LEVEL_ERROR, "[MONITOR] Failed to allocate update notification!\n");
            }

            log_message(LOG_LEVEL_INFO, "[MONITOR] Client %d updated.\n", clientID);
        }

        log_message(LOG_LEVEL_DEBUG, "\tname: '%s'\n", client->name);
        log_message(LOG_LEVEL_DEBUG, "\tbind: '%s'\n", binding_to_string(client->binding));
        log_message(LOG_LEVEL_DEBUG, "\tlifetime: %d\n", client->lifetime);
        log_message(LOG_LEVEL_DEBUG, "\tobjects: ");
        for (obj = client->objectList; obj != NULL; obj = obj->next)
        {
            if (obj->instanceList == NULL)
            {
                log_message(LOG_LEVEL_DEBUG, "/%d, ", obj->id);
            }
            else
            {
                for (ins = obj->instanceList; ins != NULL; ins = ins->next)
                {
                    log_message(LOG_LEVEL_DEBUG, "/%d/%d, ", obj->id, ins->id);
                }
            }
        }
        log_message(LOG_LEVEL_DEBUG, "\n");
        break;

    case COAP_202_DELETED:
    {
        rest_notif_deregistration_t *deregNotif = rest_notif_deregistration_new();

        if (deregNotif != NULL)
        {
            rest_notif_deregistration_set(deregNotif, client->name);
            rest_notify_deregistration(rest, deregNotif);
        }
        else
        {
            log_message(LOG_LEVEL_ERROR, "[MONITOR] Failed to allocate deregistration notification!\n");
        }

        log_message(LOG_LEVEL_INFO, "[MONITOR] Client %d deregistered.\n", clientID);
        break;
    }
    default:
        log_message(LOG_LEVEL_INFO, "[MONITOR] Client %d status update %d.\n", clientID, status);
        break;
    }
}

int psk_find_callback(const char *name, void *data, uint8_t **psk_buffer, size_t *psk_len)
{
    database_entry_t *device_data;
    rest_list_entry_t *device_entry;
    rest_list_t *device_list = (rest_list_t *)data;

    if (device_list == NULL)
    {
        return -1;
    }

    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (memcmp(name, device_data->psk_id, device_data->psk_id_len) == 0)
        {
            *psk_buffer = device_data->psk;
            *psk_len = device_data->psk_len;
            return 0;
        }
    }

    return -1;
}

uint8_t lwm2m_buffer_send(void *session, uint8_t *buffer, size_t length, void *user_data)
{
    connection_api_t *conn_api = (connection_api_t *)user_data;

    if (session == NULL)
    {
        log_message(LOG_LEVEL_ERROR, "Failed sending %lu bytes, missing connection\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    if (conn_api->f_send(conn_api, session, buffer, length) < 0)
    {
        log_message(LOG_LEVEL_ERROR, "Failed sending %lu bytes\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    return COAP_NO_ERROR;
}

bool lwm2m_session_is_equal(void *session1, void *session2, void *userData)
{
    return (session1 == session2);
}

int lwm2m_client_validate(char *name, void *session, void *user_data)
{
    connection_api_t *api = (connection_api_t *)user_data;

    if (api->f_validate == NULL)
    {
        return 0;
    }

    return api->f_validate(name, session);
}

int main(int argc, char *argv[])
{
    struct timeval tv;
    int res;
    rest_context_t rest;
    connection_api_t *conn_api;
    uint8_t buffer[1500];
    void *connection;

    static settings_t settings =
    {
        .http = {
            .port = 8888,
            .security = {
                .private_key = NULL,
                .certificate = NULL,
                .private_key_file = NULL,
                .certificate_file = NULL,
                .jwt = {
                    .initialised = false,
                    .algorithm = JWT_ALG_HS512,
                    .secret_key = NULL,
                    .secret_key_length = 32,
                    .users_list = NULL,
                    .expiration_time = 3600,
                },
            },
        },
        .coap = {
            .security_mode = PUNICA_COAP_MODE_INSECURE,
            .port = 5555,
            .private_key_file = NULL,
            .certificate_file = NULL,
            .database_file = NULL,
        },
        .logging = {
            .level = LOG_LEVEL_WARN,
            .timestamp = false,
            .human_readable_timestamp = false,
        },
    };

    settings.http.security.jwt.users_list = rest_list_new();
    settings.http.security.jwt.secret_key = (unsigned char *) malloc(
                                                settings.http.security.jwt.secret_key_length * sizeof(unsigned char));
    rest_get_random(settings.http.security.jwt.secret_key,
                    settings.http.security.jwt.secret_key_length);

    if (settings_init(argc, argv, &settings) != 0)
    {
        return -1;
    }

    logging_init(&settings.logging);

    init_signals();

    rest_init(&rest, &settings);

    conn_api = api_init(&settings.coap, (void *)rest.devicesList, psk_find_callback);
    if (conn_api == NULL)
    {
        return -1;
    }

    /* Socket section */
    log_message(LOG_LEVEL_INFO, "Creating coap socket on port %d\n", settings.coap.port);

    res = conn_api->f_start(conn_api);
    if (res < 0)
    {
        log_message(LOG_LEVEL_FATAL, "Failed to create socket!\n");
        return -1;
    }

    /* Server section */
    rest.lwm2m = lwm2m_init(NULL);
    if (rest.lwm2m == NULL)
    {
        log_message(LOG_LEVEL_FATAL, "Failed to create LwM2M server!\n");
        return -1;
    }

    rest.lwm2m->userData = conn_api;

    lwm2m_set_monitoring_callback(rest.lwm2m, client_monitor_cb, &rest);

    /* REST server section */
    struct _u_instance instance;

    log_message(LOG_LEVEL_INFO, "Creating http socket on port %u\n", settings.http.port);
    if (ulfius_init_instance(&instance, settings.http.port, NULL, NULL) != U_OK)
    {
        log_message(LOG_LEVEL_FATAL, "Failed to initialize REST server!\n");
        return -1;
    }

    /*
     * mbed Device Connector based api
     * https://docs.mbed.com/docs/mbed-device-connector-web-interfaces/en/latest/api-reference/
     */

    // Endpoints
    ulfius_add_endpoint_by_val(&instance, "GET", "/endpoints", NULL, 10,
                               &rest_endpoints_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "GET", "/endpoints", ":name", 10,
                               &rest_endpoints_name_cb, &rest);
    // Devices
    ulfius_add_endpoint_by_val(&instance, "GET", "/devices", NULL, 10,
                               &rest_devices_get_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "GET", "/devices", ":id", 10,
                               &rest_devices_get_name_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "PUT", "/devices", ":id", 10,
                               &rest_devices_put_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "POST", "/devices", NULL, 10,
                               &rest_devices_post_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "DELETE", "/devices", ":id", 10,
                               &rest_devices_delete_cb, &rest);

    // Resources
    ulfius_add_endpoint_by_val(&instance, "*", "/endpoints", ":name/*", 10,
                               &rest_resources_rwe_cb, &rest);

    // Notifications
    ulfius_add_endpoint_by_val(&instance, "GET", "/notification/callback", NULL, 10,
                               &rest_notifications_get_callback_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "PUT", "/notification/callback", NULL, 10,
                               &rest_notifications_put_callback_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "DELETE", "/notification/callback", NULL, 10,
                               &rest_notifications_delete_callback_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "GET", "/notification/pull", NULL, 10,
                               &rest_notifications_pull_cb, &rest);

    // Subscriptions
    ulfius_add_endpoint_by_val(&instance, "PUT", "/subscriptions", ":name/*", 10,
                               &rest_subscriptions_put_cb, &rest);
    ulfius_add_endpoint_by_val(&instance, "DELETE", "/subscriptions", ":name/*", 10,
                               &rest_subscriptions_delete_cb, &rest);

    // Version
    ulfius_add_endpoint_by_val(&instance, "GET", "/version", NULL, 1, &rest_version_cb, NULL);

    // JWT authentication
    ulfius_add_endpoint_by_val(&instance, "POST", "/authenticate", NULL, 1, &rest_authenticate_cb,
                               (void *)&settings.http.security.jwt);
    ulfius_add_endpoint_by_val(&instance, "*", "*", NULL, 3, &rest_validate_jwt_cb,
                               (void *)&settings.http.security.jwt);

    if (settings.http.security.private_key != NULL || settings.http.security.certificate != NULL)
    {
        if (security_load(&(settings.http.security)) != 0)
        {
            return -1;
        }

        if (ulfius_start_secure_framework(&instance,
                                          settings.http.security.private_key_file,
                                          settings.http.security.certificate_file) != U_OK)
        {
            log_message(LOG_LEVEL_FATAL, "Failed to start REST server!\n");
            return -1;
        }

        if (!settings.http.security.jwt.initialised)
        {
            log_message(LOG_LEVEL_WARN, "Encryption without authentication is unadvisable!\n");
        }
    }
    else
    {
        if (ulfius_start_framework(&instance) != U_OK)
        {
            log_message(LOG_LEVEL_FATAL, "Failed to start REST server!\n");
            return -1;
        }

        if (settings.http.security.jwt.initialised)
        {
            log_message(LOG_LEVEL_WARN, "Authentication without encryption is unadvisable!\n");
        }
    }

    if (settings.http.security.jwt.initialised)
    {
        if (settings.http.security.jwt.users_list->head == NULL)
        {
            log_message(LOG_LEVEL_WARN, "JWT is initialised but no users are configured properly!\n");
        }
        if (settings.http.security.jwt.secret_key == NULL)
        {
            log_message(LOG_LEVEL_WARN, "JWT is initialised but secret key is unavalable!\n");
        }
    }

    /* Main section */
    while (!restserver_quit)
    {
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        rest_lock(&rest);
        res = lwm2m_step(rest.lwm2m, &tv.tv_sec);
        if (res)
        {
            log_message(LOG_LEVEL_ERROR, "lwm2m_step() error: %d\n", res);
        }

        res = rest_step(&rest, &tv);
        if (res)
        {
            log_message(LOG_LEVEL_ERROR, "rest_step() error: %d\n", res);
        }
        rest_unlock(&rest);

        res = conn_api->f_receive(conn_api, buffer, sizeof(buffer), &connection, &tv);
        if (res < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            log_message(LOG_LEVEL_ERROR, "conn_api->f_receive() error: %d\n", res);
        }
        else if (res)
        {
            rest_lock(&rest);
            lwm2m_handle_packet(rest.lwm2m, buffer, res, connection);
            rest_unlock(&rest);
        }
    }

    ulfius_stop_framework(&instance);
    ulfius_clean_instance(&instance);

    conn_api->f_stop(conn_api);
    api_deinit(settings.coap.security_mode, conn_api);
    lwm2m_close(rest.lwm2m);
    rest_cleanup(&rest);

    jwt_cleanup(&settings.http.security.jwt);

    return 0;
}

