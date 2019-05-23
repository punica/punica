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

#include <map>
#include <memory>
#include <string>

#include <punica/rest/core.hpp>

punica::rest::CallbackFunction getCounterCallback;
punica::rest::CallbackFunction incrementCounterCallback;

class Counter
{
public:
    typedef std::unique_ptr<Counter> ptr;
    typedef std::map<std::string, Counter::ptr> map;

    Counter(punica::rest::Core &restCore,
            std::string prefix,
            std::string name);
    ~Counter();

    int get();
    void increment();

private:
    punica::rest::Core &mRestCore;
    std::string mPrefix, mName;
    int mCount;
};
