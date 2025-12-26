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

#include "epoll_multi_driver.h"

#include "netstack_log.h"
#include "request_info.h"
#if HAS_NETSTACK_CHR
#include "netstack_chr_client.h"
#endif
#ifdef HTTP_HANDOVER_FEATURE
#include "http_handover_handler.h"
#endif

namespace OHOS::NetStack::HttpOverCurl {

static constexpr size_t MAX_EPOLL_EVENTS = 10;

EpollMultiDriver::EpollMultiDriver(const std::shared_ptr<HttpOverCurl::ThreadSafeStorage<RequestInfo *>> &incomingQueue)
    : incomingQueue_(incomingQueue)
{
    Initialize();
}

void EpollMultiDriver::Initialize()
{
#ifdef HTTP_HANDOVER_FEATURE
    netHandoverHandler_ = std::make_shared<HttpHandoverHandler>();
    if (netHandoverHandler_->IsInitSuccess()) {
        netHandoverHandler_->RegisterForPolling(poller_);
    } else {
        netHandoverHandler_ = nullptr;
    }
#endif
    timeoutTimer_.RegisterForPolling(poller_);
    incomingQueue_->GetSyncEvent().RegisterForPolling(poller_);
    multi_ = curl_multi_init();
    if (!multi_) {
        NETSTACK_LOGE("Failed to initialize curl_multi handle");
        return;
    }

    static auto socketCallback = +[](CURL *easy, curl_socket_t s, int action, void *userp, void *socketp) {
        auto instance = static_cast<EpollMultiDriver *>(userp);
        return instance->MultiSocketCallback(s, action, static_cast<CurlSocketContext *>(socketp));
    };
    curl_multi_setopt(multi_, CURLMOPT_SOCKETDATA, this);
    curl_multi_setopt(multi_, CURLMOPT_SOCKETFUNCTION, socketCallback);

    static auto timerCallback = +[](CURLM *multi, long timeout_ms, void *userp) -> int {
        auto instance = static_cast<EpollMultiDriver *>(userp);
        return instance->MultiTimeoutCallback(timeout_ms);
    };
    curl_multi_setopt(multi_, CURLMOPT_TIMERDATA, this);
    curl_multi_setopt(multi_, CURLMOPT_TIMERFUNCTION, timerCallback);
    curl_multi_setopt(multi_, CURLMOPT_MAX_HOST_CONNECTIONS, 6); // 单个主机的最大连接数
    curl_multi_setopt(multi_, CURLMOPT_MAX_TOTAL_CONNECTIONS, 64); // 最大同时打开连接数
    curl_multi_setopt(multi_, CURLMOPT_MAXCONNECTS, 64); // 连接缓冲池的大小
}

EpollMultiDriver::~EpollMultiDriver()
{
    if (multi_) {
        curl_multi_cleanup(multi_);
        multi_ = nullptr;
    }
}

void EpollMultiDriver::Step(int waitEventsTimeoutMs)
{
    epoll_event events[MAX_EPOLL_EVENTS];
    int eventsToHandle = poller_.Wait(events, MAX_EPOLL_EVENTS, waitEventsTimeoutMs);
    if (eventsToHandle == -1) {
        if (errno != EINTR) {
            NETSTACK_LOGE("epoll wait error : %{public}d", errno);
        }
        return;
    }
    if (eventsToHandle == 0) {
        if (errno != EINTR && errno != EAGAIN && errno != 0) {
            NETSTACK_LOGE("epoll wait event 0 err: %{public}d", errno);
        }
        CheckMultiInfo();
    }
    for (int idx = 0; idx < eventsToHandle; ++idx) {
        if (incomingQueue_->GetSyncEvent().IsItYours(events[idx].data.fd)) {
            IncomingRequestCallback();
        } else if (timeoutTimer_.IsItYours(events[idx].data.fd)) {
            EpollTimerCallback();
#ifdef HTTP_HANDOVER_FEATURE
        } else if (netHandoverHandler_ && netHandoverHandler_->IsItHandoverEvent(events[idx].data.fd)) {
            netHandoverHandler_->HandoverRequestCallback(ongoingRequests_, multi_);
        } else if (netHandoverHandler_ && netHandoverHandler_->IsItHandoverTimeoutEvent(events[idx].data.fd)) {
            netHandoverHandler_->HandoverTimeoutCallback();
#endif
        } else { // curl socket event
            EpollSocketCallback(events[idx].data.fd);
        }
    }
}

void EpollMultiDriver::IncomingRequestCallback()
{
    auto requestsToAdd = incomingQueue_->Flush();
    for (auto &request : requestsToAdd) {
#ifdef HTTP_HANDOVER_FEATURE
        if (netHandoverHandler_ &&
            netHandoverHandler_->TryFlowControl(request, HandoverRequestType::INCOMING)) {
            continue;
        }
#endif
        ongoingRequests_[request->easyHandle] = request;
        auto ret = curl_multi_add_handle(multi_, request->easyHandle);
        if (ret != CURLM_OK) {
            NETSTACK_LOGE("curl_multi_add_handle err, ret = %{public}d %{public}s", ret, curl_multi_strerror(ret));
            continue;
        }
        
        if (request->callbacks.startedCallback) {
            request->callbacks.startedCallback(request->easyHandle, request->opaqueData);
        }
    }
}

// Update the timer after curl_multi library does its thing. Curl will
// inform us through this callback what it wants the new timeout to be,
// after it does some work.
int EpollMultiDriver::MultiTimeoutCallback(long timeoutMs)
{
    if (timeoutMs > 0) {
        timeoutTimer_.SetTimeoutMs(timeoutMs);
    } else if (timeoutMs == 0) {
        // libcurl wants us to timeout now, however setting both fields of
        // new_value.it_value to zero disarms the timer. The closest we can
        // do is to schedule the timer to fire in 1 ns.
        timeoutTimer_.SetTimeoutNs(1);
    }

    return 0;
}

// Called by main loop when our timeout expires
void EpollMultiDriver::EpollTimerCallback()
{
    timeoutTimer_.ResetEvent();
    auto rc = curl_multi_socket_action(multi_, CURL_SOCKET_TIMEOUT, 0, &stillRunning);
    if (rc != CURLM_OK) {
        NETSTACK_LOGE("curl_multi returned error = %{public}d", rc);
    }
    CheckMultiInfo();
}

#if ENABLE_HTTP_INTERCEPT
void EpollMultiDriver::HandleRedirect(CURL *easyHandle, std::shared_ptr<std::string> location, RequestInfo *requestInfo)
{
    if (easyHandle) {
        (void)curl_easy_cleanup(easyHandle);
    }
    auto context = reinterpret_cast<OHOS::NetStack::Http::RequestContext *>(requestInfo->opaqueData);
    context->options.SetUrl(location->c_str());
    delete requestInfo;
    context->IncreaseRedirectCount();
    Http::HttpExec::RequestWithoutCache(context);
}
#endif

void EpollMultiDriver::HandleCompletion(CURLMsg *message, RequestInfo *requestInfo)
{
    if (requestInfo != nullptr && requestInfo->callbacks.doneCallback) {
        requestInfo->callbacks.doneCallback(message, requestInfo->opaqueData);
    }
    delete requestInfo;
}

__attribute__((no_sanitize("cfi"))) void EpollMultiDriver::CheckMultiInfo()
{
    CURLMsg *message;
    int pending;

    while ((message = curl_multi_info_read(multi_, &pending))) {
        switch (message->msg) {
            case CURLMSG_DONE: {
                HandleCurlDoneMessage(message);
                break;
            }
            default:
                NETSTACK_LOGD("CURLMSG default");
                break;
        }
    }
}

void EpollMultiDriver::HandleCurlDoneMessage(CURLMsg *message)
{
    auto easyHandle = message->easy_handle;
#ifdef HAS_NETSTACK_CHR
#if ENABLE_HTTP_INTERCEPT
    long responseCode = 0;
    curl_easy_getinfo(easyHandle, CURLINFO_RESPONSE_CODE, &responseCode);
    if (responseCode < HTTP_STATUS_REDIRECT_START || responseCode >= HTTP_STATUS_CLIENT_ERROR_START)
#endif
    {
        ChrClient::NetStackChrClient::GetInstance().GetDfxInfoFromCurlHandleAndReport(easyHandle, message->data.result);
    }
#endif
    if (!easyHandle) {
        return;
    }
    curl_multi_remove_handle(multi_, easyHandle);
    auto requestInfo = ongoingRequests_[easyHandle];
    ongoingRequests_.erase(easyHandle);
#ifdef HTTP_HANDOVER_FEATURE
    if (netHandoverHandler_ && netHandoverHandler_->ProcessRequestErr(ongoingRequests_, multi_, requestInfo, message)) {
        return;
    }
#endif
    std::function<void()> handleCompletion = std::bind(&EpollMultiDriver::HandleCompletion, this, message, requestInfo);
#if ENABLE_HTTP_INTERCEPT
    char *location = nullptr;
    curl_easy_getinfo(easyHandle, CURLINFO_REDIRECT_URL, &location);
    NETSTACK_LOGD("Redirect responseCode: %{public}d", static_cast<int>(responseCode));
    auto context = reinterpret_cast<OHOS::NetStack::Http::RequestContext *>(requestInfo->opaqueData);
    auto interceptor = context->GetInterceptor();
    if (responseCode >= HTTP_STATUS_REDIRECT_START && responseCode < HTTP_STATUS_CLIENT_ERROR_START && location &&
        interceptor != nullptr && interceptor->IsRedirectionInterceptor()) {
        NETSTACK_LOGD("Redirect detected: %{public}s, status=%{public}d", location, static_cast<int>(responseCode));
        if (!context->IsReachRedirectLimit()) {
            auto locationPtr = std::make_shared<std::string>(location);
            std::function<void()> handleRedirect =
                std::bind(&EpollMultiDriver::HandleRedirect, this, easyHandle, locationPtr, requestInfo);
            auto interceptorCallback = interceptor->GetRedirectionInterceptorCallback();
            auto handleInfo = new RedirectionInterceptorInfo { message, locationPtr };
            auto redirectCallback =
                std::bind(interceptorCallback, context, handleRedirect, handleCompletion, handleInfo);
            NapiUtils::CreateUvQueueWorkByModuleId(context->GetEnv(), redirectCallback, context->GetModuleId());
            return;
        }
        message->data.result = CURLE_TOO_MANY_REDIRECTS;
    }
#endif
    handleCompletion();
}

int EpollMultiDriver::MultiSocketCallback(curl_socket_t socket, int action, CurlSocketContext *socketContext)
{
    switch (action) {
        case CURL_POLL_IN:
        case CURL_POLL_OUT:
        case CURL_POLL_INOUT:
            if (!socketContext) {
                auto curlSocket = new (std::nothrow) CurlSocketContext(poller_, socket, action);
                if (curlSocket == nullptr) {
                    return -1;
                }
                curl_multi_assign(multi_, socket, curlSocket);
            } else {
                socketContext->Reassign(socket, action);
            }
            break;
        case CURL_POLL_REMOVE:
            delete socketContext;
            break;
        default:
            NETSTACK_LOGE("Unexpected socket action = %{public}d", action);
    }

    return 0;
}

static int CurlPollToEpoll(int action)
{
    int kind = (((static_cast<unsigned int>(action)) & CURL_POLL_IN) ? EPOLLIN : (EPOLLIN & ~EPOLLIN)) |
               (((static_cast<unsigned int>(action)) & CURL_POLL_OUT) ? EPOLLOUT : (EPOLLOUT & ~EPOLLOUT));
    return kind;
}

EpollMultiDriver::CurlSocketContext::CurlSocketContext(HttpOverCurl::Epoller &poller, curl_socket_t sockDescriptor,
                                                       int action)
    : poller_(poller), socketDescriptor_(sockDescriptor)
{
    int kind = CurlPollToEpoll(action);
    poller_.RegisterMe(socketDescriptor_, kind);
}

void EpollMultiDriver::CurlSocketContext::Reassign(curl_socket_t sockDescriptor, int action)
{
    poller_.UnregisterMe(socketDescriptor_);
    socketDescriptor_ = sockDescriptor;
    int kind = CurlPollToEpoll(action);
    poller_.RegisterMe(socketDescriptor_, kind);
}

EpollMultiDriver::CurlSocketContext::~CurlSocketContext()
{
    poller_.UnregisterMe(socketDescriptor_);
}

// Called by main loop when we get action on a multi socket file descriptor
void EpollMultiDriver::EpollSocketCallback(int fd)
{
    int action = CURL_CSELECT_IN | CURL_CSELECT_OUT;
    auto rc = curl_multi_socket_action(multi_, fd, action, &stillRunning);
    if (rc != CURLM_OK) {
        NETSTACK_LOGE("curl_multi returned error = %{public}d", rc);
    }
    CheckMultiInfo();

    if (stillRunning <= 0) {
        timeoutTimer_.Stop();
    }
}

} // namespace OHOS::NetStack::HttpOverCurl
