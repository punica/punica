# Provides PUNICA_SOURCES variable and defines 'LWM2M_SERVER_MODE'

set(PUNICA_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})

set(PUNICA_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/restserver.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-core.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-core-types.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-endpoints.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-resources.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-notifications.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-subscriptions.c
    ${CMAKE_CURRENT_LIST_DIR}/linked_list.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-utils.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-authentication.c
    ${CMAKE_CURRENT_LIST_DIR}/rest-devices.c
    ${CMAKE_CURRENT_LIST_DIR}/logging.c
    ${CMAKE_CURRENT_LIST_DIR}/settings.c
    ${CMAKE_CURRENT_LIST_DIR}/security.c
    ${CMAKE_CURRENT_LIST_DIR}/database.c
    )

add_definitions(-DLWM2M_SERVER_MODE)
