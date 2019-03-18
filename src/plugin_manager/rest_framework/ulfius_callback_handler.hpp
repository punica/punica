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

#ifndef PUNICA_PLUGIN_MANAGER_REST_ULFIUS_CALLBACK_HANDLER_HPP
#define PUNICA_PLUGIN_MANAGER_REST_ULFIUS_CALLBACK_HANDLER_HPP

#include <punica/rest/callback_handler.hpp>

#ifdef __cplusplus
extern "C" {
#endif

#include <ulfius.h>

#ifdef __cplusplus
}
#endif

class UlfiusCallbackHandler: public punica::rest::CallbackHandler
{
public:
    UlfiusCallbackHandler(struct _u_instance *uInstance,
                          const std::string method,
                          const std::string prefix,
                          const std::string format,
                          unsigned int priority,
                          punica::rest::CallbackFunction handlerFunction,
                          void *handlerContext);
    ~UlfiusCallbackHandler();

private:
    struct _u_instance *mUlfiusInstance;
    std::string mMethod, mUrlPrefix, mUrlFormat;
    punica::rest::CallbackFunction mFunction;
    void *mContext;

    static int ulfiusCallback(const struct _u_request *u_request,
                              struct _u_response *u_response,
                              void *handlerContext);
};

#endif // PUNICA_PLUGIN_MANAGER_REST_ULFIUS_CALLBACK_HANDLER_HPP
