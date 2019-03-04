/*
 * MIT License
 *
 * Copyright (c) 2018 8devices
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef ULFIUS_REST_FRAMEWORK_HPP
#define ULFIUS_REST_FRAMEWORK_HPP

#include "rest_framework.hpp"
#include "callback_handler.hpp"

std::map<std::string, std::string> ulfiusToStdMap(struct _u_map *ulfius_map);

class UlfiusRestFramework: public RestFramework
{
public:
    UlfiusRestFramework(struct _u_instance *instance);
    ~UlfiusRestFramework();

    void startFramework();
    void startSecureFramework(std::string private_key_file, std::string certificate_file);
    void stopFramework();

    void addHandler(const std::string method,
                    const std::string url_prefix,
                    unsigned int priority,
                    callback_function_t handler_function,
                    void *handler_context);

private:
    static int ulfiusCallback(const struct _u_request *u_request,
                              struct _u_response *u_response, void *context);

    std::vector<CallbackHandler *> callbackHandlers;
    struct _u_instance *ulfius_instance;
};

#endif // ULFIUS_REST_FRAMEWORK_HPP
