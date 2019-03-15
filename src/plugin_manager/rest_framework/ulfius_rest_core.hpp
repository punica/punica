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

#ifndef PUNICA_PLUGIN_MANAGER_REST_ULFIUS_REST_CORE_HPP
#define PUNICA_PLUGIN_MANAGER_REST_ULFIUS_REST_CORE_HPP

#include <punica/rest/core.hpp>
#include <punica/rest/callback_handler.hpp>

std::map<std::string, std::string> ulfiusToStdMap(struct _u_map *ulfius_map);

class UlfiusRestCore: public punica::rest::Core
{
public:
    UlfiusRestCore(struct _u_instance *instance);
    ~UlfiusRestCore();

    void addHandler(const std::string method,
                    const std::string url_prefix,
                    unsigned int priority,
                    punica::rest::callback_function_t handler_function,
                    void *handler_context);

private:
    static int ulfiusCallback(const struct _u_request *u_request,
                              struct _u_response *u_response, void *context);

    std::vector<punica::rest::CallbackHandler *> callbackHandlers;
    struct _u_instance *ulfius_instance;
};

#endif // PUNICA_PLUGIN_MANAGER_REST_ULFIUS_REST_CORE_HPP
