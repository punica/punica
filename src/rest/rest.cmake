# Provides REST_SOURCES, REST_SOURCES_DIR variables

set(REST_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})

set(REST_SOURCES
    ${REST_SOURCES}
    ${REST_SOURCES_DIR}/rest_core.c
    ${REST_SOURCES_DIR}/rest_core_types.c
    ${REST_SOURCES_DIR}/rest_endpoints.c
    ${REST_SOURCES_DIR}/rest_resources.c
    ${REST_SOURCES_DIR}/rest_notifications.c
    ${REST_SOURCES_DIR}/rest_subscriptions.c
    ${REST_SOURCES_DIR}/rest_utils.c
    ${REST_SOURCES_DIR}/rest_authentication.c
    ${REST_SOURCES_DIR}/rest_devices.c
    )
