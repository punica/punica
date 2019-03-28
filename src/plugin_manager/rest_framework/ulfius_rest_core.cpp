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

#include "ulfius_rest_core.hpp"
#include "ulfius_callback_handler.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include <ulfius.h>

#ifdef __cplusplus
} // extern "C"
#endif

UlfiusRestCore::UlfiusRestCore(struct _u_instance *instance):
    mUlfiusInstance(instance)
{ }

UlfiusRestCore::~UlfiusRestCore()
{
    mCallbackHandlers.clear();
}

bool UlfiusRestCore::addCallbackHandler(const std::string method,
                                        const std::string urlPrefix,
                                        const std::string urlFormat,
                                        unsigned int priority,
                                        punica::rest::CallbackFunction *handlerFunction,
                                        void *handlerContext)
{
    UlfiusCallbackHandler::ptr callbackHandler(
        new UlfiusCallbackHandler(mUlfiusInstance,
                                  method, urlPrefix, urlFormat,
                                  priority, handlerFunction, handlerContext));

    removeCallbackHandler(method, urlPrefix, urlFormat);

    mCallbackHandlers.push_back(std::move(callbackHandler));

    return true;
}

bool UlfiusRestCore::removeCallbackHandler(const std::string method,
                                           const std::string urlPrefix,
                                           const std::string urlFormat)
{
    UlfiusCallbackHandler::vector::iterator callbackIterator =
        mCallbackHandlers.begin();

    while (callbackIterator != mCallbackHandlers.end())
    {
        if (((*callbackIterator)->getMethod() == method)
            && ((*callbackIterator)->getUrlPrefix() == urlPrefix)
            && ((*callbackIterator)->getUrlFormat() == urlFormat))
        {
            mCallbackHandlers.erase(callbackIterator);
            return true;
        }

        ++callbackIterator;
    }

    return false;
}
