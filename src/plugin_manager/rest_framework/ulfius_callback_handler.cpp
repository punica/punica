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

#include "ulfius_callback_handler.hpp"

#include "ulfius_request.hpp"
#include "ulfius_response.hpp"

UlfiusCallbackHandler::UlfiusCallbackHandler(struct _u_instance *uInstance,
                                             const std::string method,
                                             const std::string prefix,
                                             const std::string format,
                                             unsigned int priority,
                                             punica::rest::CallbackFunction function,
                                             void *context):
    mUlfiusInstance(uInstance),
    mMethod(method),
    mUrlPrefix(prefix),
    mUrlFormat(format),
    mFunction(function),
    mContext(context)
{
    ulfius_add_endpoint_by_val(mUlfiusInstance, mMethod.c_str(),
                               mUrlPrefix.c_str(), mUrlFormat.c_str(),
                               priority, &ulfiusCallback, this);
}

UlfiusCallbackHandler::~UlfiusCallbackHandler()
{
    ulfius_remove_endpoint_by_val(mUlfiusInstance, mMethod.c_str(),
                                  mUrlPrefix.c_str(), mUrlFormat.c_str());
}

int UlfiusCallbackHandler::ulfiusCallback(const struct _u_request *u_request,
                                          struct _u_response *u_response,
                                          void *handlerContext)
{
    UlfiusCallbackHandler *handler =
        static_cast<UlfiusCallbackHandler *>(handlerContext);
    punica::rest::StatusCode statusCode;

    UlfiusRequest request(u_request);
    UlfiusResponse response(u_response);

    statusCode = handler->mFunction(&request, &response, handler->mContext);

    switch (statusCode)
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
