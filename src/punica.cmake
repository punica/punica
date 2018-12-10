# Provides PUNICA_SOURCES variable and defines 'LWM2M_SERVER_MODE'

set(PUNICA_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})

set(PUNICA_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/punica.c
    ${CMAKE_CURRENT_LIST_DIR}/rest_core.c
    ${CMAKE_CURRENT_LIST_DIR}/rest_core_types.c
    ${CMAKE_CURRENT_LIST_DIR}/rest_endpoints.c
    ${CMAKE_CURRENT_LIST_DIR}/rest_resources.c
    ${CMAKE_CURRENT_LIST_DIR}/rest_notifications.c
    ${CMAKE_CURRENT_LIST_DIR}/rest_subscriptions.c
    ${CMAKE_CURRENT_LIST_DIR}/linked_list.c
    ${CMAKE_CURRENT_LIST_DIR}/rest_utils.c
    ${CMAKE_CURRENT_LIST_DIR}/rest_authentication.c
    ${CMAKE_CURRENT_LIST_DIR}/logging.c
    ${CMAKE_CURRENT_LIST_DIR}/settings.c
    ${CMAKE_CURRENT_LIST_DIR}/security.c
    )

add_definitions(-DLWM2M_SERVER_MODE)
