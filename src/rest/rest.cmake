# Provides REST_SOURCES, REST_SOURCES_DIR variables

set(REST_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})

set(REST_SOURCES
    ${REST_SOURCES}
    ${REST_SOURCES_DIR}/rest-core.c
    ${REST_SOURCES_DIR}/rest-core-types.c
    ${REST_SOURCES_DIR}/rest-endpoints.c
    ${REST_SOURCES_DIR}/rest-resources.c
    ${REST_SOURCES_DIR}/rest-notifications.c
    ${REST_SOURCES_DIR}/rest-subscriptions.c
    ${REST_SOURCES_DIR}/rest-utils.c
    ${REST_SOURCES_DIR}/rest-authentication.c
    ${REST_SOURCES_DIR}/rest-devices.c
    )
