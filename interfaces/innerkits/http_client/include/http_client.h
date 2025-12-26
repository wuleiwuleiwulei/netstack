/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMUNICATIONNETSTACK_HTTP_CLIENT_H
#define COMMUNICATIONNETSTACK_HTTP_CLIENT_H

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "http_client_error.h"
#include "http_client_request.h"
#include "http_client_task.h"

namespace OHOS::NetStack::HttpOverCurl {
    struct TransferCallbacks;
}

namespace OHOS {
namespace NetStack {
namespace HttpClient {
class HttpSession {
public:
    /**
     * Gets the singleton instance of HttpSession.
     * @return The singleton instance of HttpSession.
     */
    static HttpSession &GetInstance();

    /**
     * Creates an HTTP client task with the provided request.
     * @param request The HTTP request to be executed.
     * @return A shared pointer to the created HttpClientTask object.
     */
    [[nodiscard]] std::shared_ptr<HttpClientTask> CreateTask(const HttpClientRequest &request);

    /**
     * Creates an HTTP client task with the provided request and file path.
     * @param request The HTTP request to be executed.
     * @param type The type of the task.
     * @param filePath The file path to read the uploaded file (applicable for upload tasks).
     * @return A shared pointer to the created HttpClientTask object.
     */
    [[nodiscard]] std::shared_ptr<HttpClientTask> CreateTask(const HttpClientRequest &request, TaskType type,
                                                             const std::string &filePath);

private:
    friend class HttpClientTask;

    /**
     * Default constructor.
     */
    HttpSession();
    ~HttpSession();

    /**
     * Starts the specified HTTP client task.
     * @param ptr A shared pointer to the HttpClientTask object.
     */
    void StartTask(const std::shared_ptr<HttpClientTask> &ptr);

    /**
     * Set RequestInfo callbacks.
     * @param callbacks A structure object of callback functions for RequestInfo.
     * @param ptr A shared pointer to the HttpClientTask object.
     */
    void SetRequestInfoCallbacks(
        HttpOverCurl::TransferCallbacks &callbacks, const std::shared_ptr<HttpClientTask> &ptr);
};
} // namespace HttpClient
} // namespace NetStack
} // namespace OHOS

#endif // COMMUNICATIONNETSTACK_HTTP_CLIENT_H