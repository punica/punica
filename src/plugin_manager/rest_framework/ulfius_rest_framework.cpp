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

#include "ulfius_rest_framework.hpp"
#include "ulfius_request.hpp"
#include "ulfius_response.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include <ulfius.h>

#include "ulfius_rest_framework.h"

CUlfiusRestFramework *new_UlfiusRestFramework(struct _u_instance *instance)
{
    return reinterpret_cast<CUlfiusRestFramework *>(new UlfiusRestFramework(instance));
}
void delete_UlfiusRestFramework(CUlfiusRestFramework *c_framework)
{
    delete reinterpret_cast<UlfiusRestFramework *>(c_framework);
}
void UlfiusRestFramework_startFramework(CUlfiusRestFramework *c_framework)
{
    UlfiusRestFramework *framework = reinterpret_cast<UlfiusRestFramework *>(c_framework);
    framework->startFramework();
}
void UlfiusRestFramework_startSecureFramework(CUlfiusRestFramework *c_framework,
                                              const char *c_private_key_file, const char *c_certificate_file)
{
    UlfiusRestFramework *framework = reinterpret_cast<UlfiusRestFramework *>(c_framework);
    const std::string private_key_file(c_private_key_file);
    const std::string certificate_file(c_certificate_file);

    framework->startSecureFramework(private_key_file, certificate_file);
}
void UlfiusRestFramework_stopFramework(CUlfiusRestFramework *c_framework)
{
    UlfiusRestFramework *framework = reinterpret_cast<UlfiusRestFramework *>(c_framework);

    framework->stopFramework();
}
void UlfiusRestFramework_addHandler(CUlfiusRestFramework *c_framework,
                                    const char *method, const char *url_prefix, unsigned int priority,
                                    c_callback_function_t c_handler_function, void *handler_context)
{
    UlfiusRestFramework *framework = reinterpret_cast<UlfiusRestFramework *>(c_framework);
    callback_function_t handler_function = reinterpret_cast<callback_function_t>(c_handler_function);

    framework->addHandler(method, url_prefix, priority, handler_function, handler_context);
}

#ifdef __cplusplus
} // extern "C"
#endif

UlfiusRestFramework::UlfiusRestFramework(struct _u_instance *instance):
    ulfius_instance(instance)
{ }
UlfiusRestFramework::~UlfiusRestFramework()
{
    for (std::vector<CallbackHandler *>::size_type index = 0;
         index < callbackHandlers.size(); ++index)
    {
        delete callbackHandlers[index];
    }
}
void UlfiusRestFramework::startFramework()
{
    ulfius_start_framework(ulfius_instance);
}
void UlfiusRestFramework::startSecureFramework(const std::string private_key_file,
                                               const std::string certificate_file)
{
    ulfius_start_secure_framework(ulfius_instance, private_key_file.c_str(),
                                  certificate_file.c_str());
}
void UlfiusRestFramework::stopFramework()
{
    ulfius_stop_framework(ulfius_instance);
}
int UlfiusRestFramework::ulfiusCallback(const struct _u_request *u_request,
                                        struct _u_response *u_response, void *context)
{
    StatusCode callback_status_code;

    UlfiusRequest request(u_request);
    UlfiusResponse response(u_response);

    CallbackHandler *handler = reinterpret_cast<CallbackHandler *>(context);
    callback_status_code = handler->function(&request, &response, handler->context);

    switch (callback_status_code)
    {
    case information_continue:
        return U_CALLBACK_CONTINUE;

    case success_ok:
    case success_created:
    case success_accepted:
    case success_no_content:
    case success_reset_content:

    case client_error:
    case client_error_forbidden:
    case client_error_not_found:
    case client_error_method_not_allowed:
    case client_error_not_acceptable:
        return U_CALLBACK_COMPLETE;

    case client_error_unauthorized:
        return U_CALLBACK_UNAUTHORIZED;

    case server_error_internal_server_error:
        return U_CALLBACK_ERROR;

    default:
        return U_CALLBACK_ERROR;
    }
}

void UlfiusRestFramework::addHandler(
    const std::string method, const std::string url_prefix,
    unsigned int priority, callback_function_t handler_function, void *handler_context)
{
    CallbackHandler *handler = new CallbackHandler(handler_function, handler_context);
    callbackHandlers.push_back(handler);
    ulfius_add_endpoint_by_val(ulfius_instance, method.c_str(),
                               url_prefix.c_str(), NULL, priority, &ulfiusCallback,
                               reinterpret_cast<void *>(handler));
}
