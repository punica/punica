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

#ifndef CALLBACK_HANDLER_HPP
#define CALLBACK_HANDLER_HPP

typedef int (*ulfius_callback_function_t)(const struct _u_request *, struct _u_response *, void *);

class CallbackHandler
{
public:
    CallbackHandler(callback_function_t handler_function, void *handler_context)
        : function(handler_function), context(handler_context)
    { }
    callback_function_t function;
    void *context;
};

#endif // CALLBACK_HANDLER_HPP
