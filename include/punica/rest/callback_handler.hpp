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

#ifndef PUNICA_REST_CALLBACK_HANDLER_HPP
#define PUNICA_REST_CALLBACK_HANDLER_HPP

#include <memory>

#include <punica/rest/request.hpp>
#include <punica/rest/response.hpp>

namespace punica {
namespace rest {

typedef int(*CallbackFunction)(Request::ptr, Response::ptr, void *);

class CallbackHandler
{
public:
    typedef std::unique_ptr<CallbackHandler> ptr;
    typedef std::vector<CallbackHandler::ptr> vector;

    ~CallbackHandler() { }

private:
    CallbackFunction mFunction;
    std::string mMethod, mUrlPrefix, mUrlFormat;
    void *mContext;
};

} /* namespace rest */
} /* namespace punica */

#endif // PUNICA_REST_CALLBACK_HANDLER_HPP
