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

#ifndef REST_FRAMEWORK_HPP
#define REST_FRAMEWORK_HPP

#include <string>

#include "request.hpp"
#include "response.hpp"

typedef StatusCode (*callback_function_t)(Request *, Response *, void*);

class RestFramework
{
public:
    virtual ~RestFramework() { }

    virtual void addHandler(
        const std::string method, const std::string url_prefix,
        unsigned int priority, callback_function_t handler_function, void *handler_context) = 0;
};

#endif // REST_FRAMEWORK_HPP
