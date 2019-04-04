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

#include <punica/rest/http_codes.h>

#include "counter.hpp"

int getCounterCallback(punica::rest::Request *request,
                       punica::rest::Response *response,
                       void *context)
{
    Counter *counter = reinterpret_cast<Counter *>(context);
    std::string stringCount = std::to_string(counter->get());

    response->setBody(std::vector<uint8_t>(stringCount.begin(),
                                           stringCount.end()));

    return HTTP_200_OK;
}

int incrementCounterCallback(punica::rest::Request *request,
                             punica::rest::Response *response,
                             void *context)
{
    Counter *counter = reinterpret_cast<Counter *>(context);
    counter->increment();

    return HTTP_204_NO_CONTENT;
}

Counter::Counter(punica::rest::Core &restCore,
                 std::string prefix,
                 std::string name):
    mRestCore(restCore),
    mPrefix(prefix),
    mName(name),
    mCount(0)
{
    mRestCore.addCallbackHandler("GET", mPrefix + mName, "", 21,
                                 &getCounterCallback,
                                 reinterpret_cast<void *>(this));
    mRestCore.addCallbackHandler("POST", mPrefix + mName, "", 21,
                                 &incrementCounterCallback,
                                 reinterpret_cast<void *>(this));
}

Counter::~Counter()
{
    mRestCore.removeCallbackHandler("GET", mPrefix + mName, "");
    mRestCore.removeCallbackHandler("POST", mPrefix + mName, "");
}

int Counter::get()
{
    return mCount;
}

void Counter::increment()
{
    ++mCount;
}
