/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_HTTP_HANDOVER_HANDLER_H
#define COMMUNICATIONNETSTACK_HTTP_HANDOVER_HANDLER_H

#include <map>
#include <memory>
#include <set>
#include <queue>

#include "curl/curl.h"

#include "epoller.h"
#include "thread_safe_storage.h"
#include "timeout_timer.h"
#include "manual_reset_event.h"
#include "epoll_request_handler.h"
#include "request_info.h"
#include "request_context.h"

namespace OHOS::NetStack::HttpOverCurl {
struct RequestInfo;
typedef void *(*HTTP_HAND_OVER_INIT)(const void *user,
    void (*HMS_NetworkBoost_HandoverEventCallback)(const void *),
    void (*HMS_NetworkBoost_HandoverTimerCallback)(const void *, long), const char *stackName);
typedef int32_t (*HTTP_HAND_OVER_UNINIT)(const void *handle);
typedef void (*HTTP_HAND_OVER_QUERY)(const void *handle, int32_t *status, int32_t *netId);
typedef void (*HTTP_HAND_OVER_ADD)(const void *handle, const void *userp, HttpHandoverInfo httpHandoverInfo);
typedef void (*HTTP_HAND_OVER_DEL)(const void *handle, const void *userp, bool isSuccess);
typedef HttpHandoverInfo (*HTTP_HAND_OVER_QUERY_REQUEST)(const void *handle, const void *userp);
typedef void (*HTTP_HAND_OVER_REPORT_TIMEOUT)(const void *handle);

void HandoverCallback(const void *user);
void HandoverTimerCallback(const void *user, long timeoutMs);
bool CheckSocketTime(void *user, curl_socket_t fd);
curl_socket_t OpenSocket(void *user, curlsocktype purpose, struct curl_sockaddr *addr);
int CloseSocketCallback(void *user, curl_socket_t fd);

class HttpHandoverHandler {
public:
    enum { INIT, START, CONTINUE, END, FATAL, TIMEOUT };
    explicit HttpHandoverHandler();
    ~HttpHandoverHandler();

    bool IsInitSuccess();
    bool TryFlowControl(RequestInfo* requestInfo, int32_t requestType);
    void HandoverRequestCallback(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi);
    void HandoverTimeoutCallback();
    void RegisterForPolling(Epoller &poller) const;
    bool IsItHandoverEvent(FileDescriptor descriptor) const;
    bool IsItHandoverTimeoutEvent(FileDescriptor descriptor) const;
    void SetHandoverEvent();
    void SetHandoverTimeoutEvent(long timeoutMs);
    bool ProcessRequestErr(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi,
        RequestInfo *requestInfo, CURLMsg *msg);
    bool Initialize();
    void SetCallback(RequestInfo *request);
    void SetHandoverInfo(RequestInfo *requestInfo);
    void HandoverQuery();
    bool CheckSocketOpentimeLessThanEndTime(curl_socket_t fd);
    void SetSocketOpenTime(curl_socket_t fd);
    void EraseFd(curl_socket_t fd);
    bool RetransRequest(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi, RequestInfo *request);
    bool CheckRequestCanRetrans(RequestInfo *request, int32_t requestType, CURLcode result);
    void UndoneRequestHandle(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi);
    int32_t IsRequestInQueue(CURL *easyHandle);
    int32_t IsRequestRead(CURL *easyHandle);
    int32_t IsRequestRead(CURL *easyHandle, time_t &recvtime, time_t &sendtime);
    bool IsNetworkErrorTypeCorrect(CURLcode result);
    bool ProcessRequestNetError(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi,
                              RequestInfo *requestInfo, CURLMsg *msg);
    void AddRequest(RequestInfo *requestInfo, int32_t handoverReason);
    void DelRequest(RequestInfo *requestInfo);
    int32_t GetStatus();
    void SetStatus(int32_t status);
    int32_t GetNetId();
    void SetNetId(int32_t netId);

private:
    void *netHandoverHandler_ = nullptr;
    void *httpHandoverManager_ = nullptr;
    std::unique_ptr<ManualResetEvent> handOverEvent_;
    std::unique_ptr<HttpOverCurl::TimeoutTimer> handOverTimerEvent_;

    HTTP_HAND_OVER_INIT httpHandoverInit_ = nullptr;
    HTTP_HAND_OVER_UNINIT httpHandoverUninit_ = nullptr;
    HTTP_HAND_OVER_QUERY httpHandoverQuery_ = nullptr;
    HTTP_HAND_OVER_ADD httpHandoverAddRequest_ = nullptr;
    HTTP_HAND_OVER_DEL httpHandoverDelRequest_ = nullptr;
    HTTP_HAND_OVER_QUERY_REQUEST httpHandoverQueryRequest_ = nullptr;
    HTTP_HAND_OVER_REPORT_TIMEOUT httpHandoverReportTimeout_ = nullptr;
    std::set<RequestInfo *> handoverQueue_;
    std::map<curl_socket_t, int> socketopentime_;
    std::map<RequestInfo *, int> requestEndtime_;
    bool initsuccess_;
    int endTime_ = 0;
    int timeoutTime_ = 0;
    int retrans_ = 0;
    int32_t status_ = HttpHandoverHandler::INIT;
    int32_t netId_ = 0;
};

}  // namespace OHOS::NetStack::HttpOverCurl

#endif  // COMMUNICATIONNETSTACK_HTTP_HANOVER_HANDLER_H