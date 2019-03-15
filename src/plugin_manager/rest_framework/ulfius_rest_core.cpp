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

#include <cstring>

#include "ulfius_rest_core.hpp"
#include "ulfius_request.hpp"
#include "ulfius_response.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include <ulfius.h>

#include "ulfius_rest_core.h"

CUlfiusRestCore *new_UlfiusRestCore(struct _u_instance *instance)
{
    return reinterpret_cast<CUlfiusRestCore *>(new UlfiusRestCore(instance));
}

void delete_UlfiusRestCore(CUlfiusRestCore *c_core)
{
    delete reinterpret_cast<UlfiusRestCore *>(c_core);
}

#ifdef __cplusplus
} // extern "C"
#endif

UlfiusRestCore::UlfiusRestCore(struct _u_instance *instance):
    ulfius_instance(instance)
{ }

UlfiusRestCore::~UlfiusRestCore()
{
    for (std::vector<punica::rest::CallbackHandler *>::size_type index = 0;
         index < callbackHandlers.size(); ++index)
    {
        delete callbackHandlers[index];
    }
}

int UlfiusRestCore::ulfiusCallback(const struct _u_request *u_request,
                                   struct _u_response *u_response,
                                   void *context)
{
    punica::rest::StatusCode callback_status_code;

    UlfiusRequest request(u_request);
    UlfiusResponse response(u_response);

    punica::rest::CallbackHandler *handler =
        reinterpret_cast<punica::rest::CallbackHandler *>(context);
    callback_status_code = handler->function(&request,
                                             &response,
                                             handler->context);

    switch (callback_status_code)
    {
    case punica::rest::information_continue:
        return U_CALLBACK_CONTINUE;

    case punica::rest::success_ok:
    case punica::rest::success_created:
    case punica::rest::success_accepted:
    case punica::rest::success_no_content:
    case punica::rest::success_reset_content:

    case punica::rest::client_error:
    case punica::rest::client_error_forbidden:
    case punica::rest::client_error_not_found:
    case punica::rest::client_error_method_not_allowed:
    case punica::rest::client_error_not_acceptable:
        return U_CALLBACK_COMPLETE;

    case punica::rest::client_error_unauthorized:
        return U_CALLBACK_UNAUTHORIZED;

    case punica::rest::server_error_internal_server_error:
        return U_CALLBACK_ERROR;

    default:
        return U_CALLBACK_ERROR;
    }
}

void UlfiusRestCore::addHandler(const std::string method,
                                const std::string url_prefix,
                                unsigned int priority,
                                punica::rest::callback_function_t handler_function,
                                void *handler_context)
{
    punica::rest::CallbackHandler *handler =
        new punica::rest::CallbackHandler(handler_function, handler_context);

    callbackHandlers.push_back(handler);

    ulfius_add_endpoint_by_val(ulfius_instance, method.c_str(),
                               url_prefix.c_str(), NULL, priority,
                               &ulfiusCallback,
                               reinterpret_cast<void *>(handler));
}
