/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_EPOLL_MULTI_DRIVER_H
#define COMMUNICATIONNETSTACK_EPOLL_MULTI_DRIVER_H

#include <map>
#include <memory>

#include "curl/curl.h"

#if ENABLE_HTTP_INTERCEPT
#include "http_exec.h"
#endif


#include "epoller.h"
#include "thread_safe_storage.h"
#include "timeout_timer.h"
#ifdef HTTP_HANDOVER_FEATURE
#include "http_handover_handler.h"
#endif

namespace OHOS::NetStack::HttpOverCurl {

struct RequestInfo;

constexpr long HTTP_STATUS_REDIRECT_START = 300;
constexpr long HTTP_STATUS_CLIENT_ERROR_START = 400;

class EpollMultiDriver {
public:
    EpollMultiDriver() = delete;
    explicit EpollMultiDriver(const std::shared_ptr<HttpOverCurl::ThreadSafeStorage<RequestInfo *>> &incomingQueue);
    ~EpollMultiDriver();

    void Step(int waitEventsTimeoutMs);

private:
    class CurlSocketContext {
    public:
        CurlSocketContext(HttpOverCurl::Epoller &poller, curl_socket_t socket, int action);
        void Reassign(curl_socket_t socket, int action);
        ~CurlSocketContext();

    private:
        HttpOverCurl::Epoller &poller_;
        curl_socket_t socketDescriptor_;
    };

    int MultiTimeoutCallback(long timeoutMs);
    int MultiSocketCallback(curl_socket_t s, int action, CurlSocketContext *socketContext);

    void EpollTimerCallback();
    void EpollSocketCallback(int fd);

    void CheckMultiInfo();
    void HandleCurlDoneMessage(CURLMsg *message);

    void Initialize();
    void IncomingRequestCallback();

#if ENABLE_HTTP_INTERCEPT
    void HandleRedirect(CURL *easyHandle, std::shared_ptr<std::string> location, RequestInfo *requestInfo);
#endif
    void HandleCompletion(CURLMsg *message, RequestInfo *requestInfo);

    std::shared_ptr<HttpOverCurl::ThreadSafeStorage<RequestInfo *>> incomingQueue_;

    HttpOverCurl::Epoller poller_;
    HttpOverCurl::TimeoutTimer timeoutTimer_;

    CURLM *multi_ = nullptr;
    // Number of running handles
    int stillRunning = 0;

    std::map<CURL *, RequestInfo *> ongoingRequests_;
#ifdef HTTP_HANDOVER_FEATURE
    std::shared_ptr<HttpHandoverHandler> netHandoverHandler_;
#endif
};

} // namespace OHOS::NetStack::HttpOverCurl

#endif // COMMUNICATIONNETSTACK_EPOLL_MULTI_DRIVER_H
