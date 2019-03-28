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

#include <map>
#include <punica/rest/core.hpp>

#include "ulfius_callback_handler.hpp"

std::map<std::string, std::string> ulfiusToStdMap(struct _u_map *ulfius_map);

class UlfiusRestCore: public punica::rest::Core
{
public:
    UlfiusRestCore(struct _u_instance *instance);
    ~UlfiusRestCore();

    bool addCallbackHandler(const std::string method,
                            const std::string urlPrefix,
                            const std::string urlFormat,
                            unsigned int priority,
                            punica::rest::CallbackFunction *handler_function,
                            void *handler_context);
    bool removeCallbackHandler(const std::string method,
                               const std::string urlPrefix,
                               const std::string urlFormat);

private:
    UlfiusCallbackHandler::vector mCallbackHandlers;
    struct _u_instance *mUlfiusInstance;
};

#endif // PUNICA_PLUGIN_MANAGER_REST_ULFIUS_REST_CORE_HPP
