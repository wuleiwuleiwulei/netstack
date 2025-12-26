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

#include <dlfcn.h>
#include "http_handover_handler.h"
#include "netstack_log.h"
#include "request_info.h"
#include "request_context.h"

namespace OHOS::NetStack::HttpOverCurl {

constexpr const char *const METHOD_GET = "GET";
constexpr const char *const METHOD_HEAD = "HEAD";
constexpr const char *const METHOD_OPTIONS = "OPTIONS";
constexpr const char *const METHOD_TRACE = "TRACE";
constexpr const long TIMEOUT_IMMEDIATE_NS = 1000;
constexpr const int32_t UNINIT_RET_INITIAL = -1;
constexpr const int32_t UNINIT_SUCCESS_CODE = 0;

HttpHandoverHandler::HttpHandoverHandler()
    : handOverEvent_(std::make_unique<ManualResetEvent>(true)),
      handOverTimerEvent_(std::make_unique<HttpOverCurl::TimeoutTimer>())
{
    initsuccess_ = Initialize();
}

void HandoverCallback(const void *user)
{
    if (user == nullptr) {
        NETSTACK_LOGE("handover callback user is nullptr");
        return;
    }

    HttpHandoverHandler* const handoverhandler = reinterpret_cast<HttpHandoverHandler*>(const_cast<void*>(user));
    handoverhandler->SetHandoverEvent();
}

void HandoverTimerCallback(const void *user, long timeoutMs)
{
    NETSTACK_LOGD("HandoverTimerCallback enter, set timeout %{public}ld ms.", timeoutMs);
    if (user == nullptr) {
        NETSTACK_LOGE("timer callback user is nullptr");
        return;
    }

    HttpHandoverHandler* const handoverHandler = reinterpret_cast<HttpHandoverHandler*>(const_cast<void*>(user));
    handoverHandler->SetHandoverTimeoutEvent(timeoutMs);
}

bool CheckSocketTime(void *user, curl_socket_t fd)
{
    auto handover = static_cast<HttpHandoverHandler *>(user);
    if (handover && handover->CheckSocketOpentimeLessThanEndTime(fd)) {  // LCOV_EXCL_LINE
        return false;
    }
    return true;
}

curl_socket_t OpenSocket(void *user, curlsocktype purpose, struct curl_sockaddr *addr)
{
    curl_socket_t sockfd = socket(addr->family, addr->socktype, addr->protocol);
    if (sockfd < 0) {  // LCOV_EXCL_LINE
        NETSTACK_LOGE("Failed to open socket: %{public}d, errno: %{public}d", sockfd, errno);
        return -1;
    }
    auto handover = static_cast<HttpHandoverHandler *>(user);
    if (handover) {
        handover->SetSocketOpenTime(sockfd);
    }
    return sockfd;
}

int CloseSocketCallback(void *user, curl_socket_t fd)
{
    auto handover = static_cast<HttpHandoverHandler *>(user);
    if (handover) {
        handover->EraseFd(fd);
    }
    int ret = close(fd);
    if (ret < 0) {  // LCOV_EXCL_LINE
        NETSTACK_LOGE("Failed to close socket: %{public}d, errno: %{public}d", fd, errno);
        return ret;
    }
    return 0;
}

static bool IsIoError(CURLcode result)
{
    if (result == CURLE_SEND_ERROR || result == CURLE_RECV_ERROR) {
        return true;
    }
    return false;
}

static bool IsConnectError(CURLcode result)
{
    if (result == CURLE_COULDNT_RESOLVE_HOST || result == CURLE_COULDNT_CONNECT ||
        result == CURLE_SSL_CONNECT_ERROR || result == CURLE_QUIC_CONNECT_ERROR) {
        return true;
    }
    return false;
}

bool HttpHandoverHandler::IsNetworkErrorTypeCorrect(CURLcode result)
{
    if (IsIoError(result) || IsConnectError(result)) {
        return true;
    }
    return false;
}

bool HttpHandoverHandler::IsInitSuccess()
{
    return initsuccess_;
}

bool HttpHandoverHandler::Initialize()
{
    const std::string HTTP_HANDOVER_WRAPPER_PATH = "/system/lib64/libhttp_handover.z.so";
    netHandoverHandler_ = dlopen(HTTP_HANDOVER_WRAPPER_PATH.c_str(), RTLD_NOW);
    if (netHandoverHandler_ == nullptr) {  // LCOV_EXCL_LINE
        NETSTACK_LOGE("libhttp_handover.z.so was not loaded, error: %{public}s", dlerror());
        return false;
    }
    httpHandoverInit_ = (HTTP_HAND_OVER_INIT)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerInit");
    httpHandoverUninit_ =
        (HTTP_HAND_OVER_UNINIT)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerUninit");
    httpHandoverQuery_ =
        (HTTP_HAND_OVER_QUERY)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerQuery");
    httpHandoverAddRequest_ =
        (HTTP_HAND_OVER_ADD)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerAddRequest");
    httpHandoverDelRequest_ =
        (HTTP_HAND_OVER_DEL)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerDelRequest");
    httpHandoverQueryRequest_ =
        (HTTP_HAND_OVER_QUERY_REQUEST)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerQueryRequest");
    httpHandoverReportTimeout_ =
        (HTTP_HAND_OVER_REPORT_TIMEOUT)dlsym(netHandoverHandler_, "HMS_NetworkBoost_HttpHandoverManagerReportTimeout");
    // LCOV_EXCL_START
    bool hasFuncNull = (httpHandoverInit_ == nullptr || httpHandoverUninit_ == nullptr ||
        httpHandoverQuery_ == nullptr || httpHandoverAddRequest_ == nullptr || httpHandoverDelRequest_ == nullptr ||
        httpHandoverQueryRequest_ == nullptr || httpHandoverReportTimeout_ == nullptr);
    // LCOV_EXCL_STOP
    if (hasFuncNull) {
        NETSTACK_LOGE("http handover wrapper symbol failed, error: %{public}s", dlerror());
        return false;
    }
    NETSTACK_LOGD("NetHandover enabled");
    httpHandoverManager_ = httpHandoverInit_(this, HandoverCallback, HandoverTimerCallback, HTTP_STACK_NAME);
    if (httpHandoverManager_ == nullptr) {
        NETSTACK_LOGE("http handover manager init fail");
        return false;
    }
    return true;
}

HttpHandoverHandler::~HttpHandoverHandler()
{
    NETSTACK_LOGD("start httpHandoverUninit_");
    int32_t ret = UNINIT_RET_INITIAL;
    if (httpHandoverManager_ != nullptr) {  // LCOV_EXCL_LINE
        ret = httpHandoverUninit_(httpHandoverManager_);
    }
    if (netHandoverHandler_ != nullptr && ret == UNINIT_SUCCESS_CODE) {  // LCOV_EXCL_LINE
        dlclose(netHandoverHandler_);
    }
    httpHandoverManager_ = nullptr;
    netHandoverHandler_ = nullptr;
    httpHandoverInit_ = nullptr;
    httpHandoverUninit_ = nullptr;
    httpHandoverQuery_ = nullptr;
    httpHandoverAddRequest_ = nullptr;
    httpHandoverDelRequest_ = nullptr;
    httpHandoverQueryRequest_ = nullptr;
    httpHandoverReportTimeout_ = nullptr;
}

void HttpHandoverHandler::RegisterForPolling(Epoller &poller) const
{
    handOverEvent_->RegisterForPolling(poller);
    handOverTimerEvent_->RegisterForPolling(poller);
}

bool HttpHandoverHandler::IsItHandoverEvent(FileDescriptor descriptor) const
{
    return handOverEvent_->IsItYours(descriptor);
}

bool HttpHandoverHandler::IsItHandoverTimeoutEvent(FileDescriptor descriptor) const
{
    return handOverTimerEvent_->IsItYours(descriptor);
}

void HttpHandoverHandler::SetHandoverEvent()
{
    handOverEvent_->Set();
}

void HttpHandoverHandler::SetHandoverTimeoutEvent(long timeoutMs)
{
    if (timeoutMs > 0) {
        handOverTimerEvent_->SetTimeoutMs(timeoutMs);
    } else if (timeoutMs == 0) {  // set a very small time means immediately trigger timeout timer
        handOverTimerEvent_->SetTimeoutNs(TIMEOUT_IMMEDIATE_NS);
    } else {  // timeoutMs < 0 means stop timeout timer
        handOverTimerEvent_->Stop();
    }
}

void HttpHandoverHandler::HandoverQuery()
{
    if (httpHandoverQuery_ == nullptr || httpHandoverManager_ == nullptr) {  // LCOV_EXCL_LINE
        NETSTACK_LOGE("nullptr param error");
        return;
    }
    httpHandoverQuery_(httpHandoverManager_, &status_, &netId_);  // LCOV_EXCL_LINE
}

bool HttpHandoverHandler::CheckSocketOpentimeLessThanEndTime(curl_socket_t fd)
{
    if (socketopentime_.count(fd) == 0) {
        return false;
    }
    bool ret = socketopentime_[fd] < endTime_;
    if (ret) {  // LCOV_EXCL_LINE
        NETSTACK_LOGD("Old fd:%{public}d fdtime:%{public}d endTime:%{public}d", (int)fd, socketopentime_[fd], endTime_);
    }
    return ret;
}

void HttpHandoverHandler::SetSocketOpenTime(curl_socket_t fd)
{
    socketopentime_[fd] = endTime_;
}

void HttpHandoverHandler::EraseFd(curl_socket_t fd)
{
    if (socketopentime_.count(fd) == 0) {
        return;
    }
    socketopentime_.erase(fd);
}

void HttpHandoverHandler::SetCallback(RequestInfo *request)
{
    curl_easy_setopt(request->easyHandle, CURLOPT_CONNREUSEDATA, this);
    curl_easy_setopt(request->easyHandle, CURLOPT_CONNREUSEFUNCTION, CheckSocketTime);

    curl_easy_setopt(request->easyHandle, CURLOPT_OPENSOCKETDATA, this);
    curl_easy_setopt(request->easyHandle, CURLOPT_OPENSOCKETFUNCTION, OpenSocket);

    curl_easy_setopt(request->easyHandle, CURLOPT_CLOSESOCKETDATA, this);
    curl_easy_setopt(request->easyHandle, CURLOPT_CLOSESOCKETFUNCTION, CloseSocketCallback);
}

bool HttpHandoverHandler::TryFlowControl(RequestInfo *requestInfo, int32_t requestType)
{
    HandoverQuery();
    if (GetStatus() == HttpHandoverHandler::FATAL) {
        NETSTACK_LOGE("Handover status fatal, feature disable.");
        return false;
    }

    SetCallback(requestInfo);
    if (GetStatus() == HttpHandoverHandler::START) {
        handoverQueue_.insert(requestInfo);
        std::string reason;
        if (requestType == HandoverRequestType::INCOMING) {
            reason = "incoming request";
        } else if (requestType == HandoverRequestType::NETWORKERROR) {
            reason = "network error";
        }
        HttpHandoverStackInfo httpHandoverStackInfo =
            requestInfo->callbacks.handoverInfoCallback(requestInfo->opaqueData);
        NETSTACK_LOGD("taskid=%{public}d, FlowControl reason:%{public}s", httpHandoverStackInfo.taskId, reason.c_str());
        AddRequest(requestInfo, requestType);
        return true;
    }
    AddRequest(requestInfo, HandoverRequestType::OLD);
    return false;
}

bool HttpHandoverHandler::RetransRequest(std::map<CURL *, RequestInfo *> &ongoingRequests,
    CURLM *multi, RequestInfo *request)
{
    auto ret = curl_multi_add_handle(multi, request->easyHandle);
    if (ret != CURLM_OK) {
        NETSTACK_LOGD("curl_multi_add_handle err, ret = %{public}d %{public}s", ret, curl_multi_strerror(ret));
        return false;
    }
    ongoingRequests[request->easyHandle] = request;
    return true;
}

bool HttpHandoverHandler::CheckRequestCanRetrans(RequestInfo *request, int32_t requestType, CURLcode result)
{
    if (request == nullptr) {  // LCOV_EXCL_LINE
        return false;
    }
    time_t recvtime = 0;
    time_t sendtime = 0;
    int32_t readFlag = IsRequestRead(request->easyHandle, recvtime, sendtime);
    if (readFlag == -1) {  // LCOV_EXCL_LINE
        return false;
    }
    
    HttpHandoverStackInfo httpHandoverStackInfo = request->callbacks.handoverInfoCallback(request->opaqueData);
    // LCOV_EXCL_START
    bool isSafe = (httpHandoverStackInfo.method == METHOD_GET || httpHandoverStackInfo.method == METHOD_HEAD ||
                   httpHandoverStackInfo.method == METHOD_OPTIONS || httpHandoverStackInfo.method == METHOD_TRACE);
    bool ret = false;
    if (IsConnectError(result) || sendtime == 0 || (isSafe && (!httpHandoverStackInfo.isInStream || readFlag == 0))) {
        ret = true;
    }
    // LCOV_EXCL_STOP
    if (requestType == HandoverRequestType::INCOMING || requestType == HandoverRequestType::NETWORKERROR) {
        return ret;
    }
    std::string type;
    if (requestType == HandoverRequestType::OLD) {
        type = "old request";
    } else {
        type = "undone request";
    }
    NETSTACK_LOGI(
        "taskid=%{public}d,requestType:%{public}s,canRetrans:%{public}d,"
        "method:%{public}s,isInStream:%{public}d,recvtime:%{public}d,sendtime:%{public}d,readTimeout:%{public}u,"
        "connecttimeout:%{public}u",
        httpHandoverStackInfo.taskId, type.c_str(), (int)ret, httpHandoverStackInfo.method.c_str(),
        httpHandoverStackInfo.isInStream, (int)recvtime, (int)sendtime, httpHandoverStackInfo.readTimeout,
        httpHandoverStackInfo.connectTimeout);
    return ret;
}

void HttpHandoverHandler::UndoneRequestHandle(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi)
{
    for (auto it = ongoingRequests.begin(); it != ongoingRequests.end();) {
        auto handle = it->first;
        auto requestInfo = it->second;
        if (CheckRequestCanRetrans(requestInfo, HandoverRequestType::UNDONE, CURLE_OK)) {
            curl_multi_remove_handle(multi, handle);
            if (RetransRequest(ongoingRequests, multi, requestInfo)) {
                ++retrans_;
                AddRequest(requestInfo, HandoverRequestType::UNDONE);
                ++it;
                continue;
            }
            // LCOV_EXCL_START
            if (requestInfo != nullptr && requestInfo->callbacks.doneCallback) {
                CURLMsg message;
                message.msg = CURLMSG_DONE;
                message.data.result = CURLE_SEND_ERROR;
                requestInfo->callbacks.doneCallback(&message, requestInfo->opaqueData);
            }
            it = ongoingRequests.erase(it);
            // LCOV_EXCL_STOP
        } else {
            ++it;
        }
    }
}

void HttpHandoverHandler::HandoverRequestCallback(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi)
{
    handOverEvent_->Reset();
    HandoverQuery();
    NETSTACK_LOGD("Enter HandoverRequestCallback status %{public}d", GetStatus());  // LCOV_EXCL_START
    if (GetStatus() == HttpHandoverHandler::START) {
        NETSTACK_LOGD("start ongoingRequests:%{public}d", (int)ongoingRequests.size());
        for (auto &request : ongoingRequests) {
            if (requestEndtime_.count(request.second) == 0) {
                requestEndtime_[request.second] = endTime_;
            }
            (void)CheckRequestCanRetrans(request.second, HandoverRequestType::OLD, CURLE_OK);
        }
    } else if (GetStatus() == HttpHandoverHandler::END || GetStatus() == HttpHandoverHandler::TIMEOUT) {
        (GetStatus() == HttpHandoverHandler::END) ? ++endTime_ : ++timeoutTime_;
        NETSTACK_LOGD("endTime:%{public}d, timeoutTime: %{public}d, ongoingRequests:%{public}d, retrans count before "
                      "end:%{public}d", endTime_, timeoutTime_, (int)ongoingRequests.size(), retrans_);
        UndoneRequestHandle(ongoingRequests, multi);

        NETSTACK_LOGD("handoverQueue_:%{public}d, retrans total count:%{public}d",
            (int)handoverQueue_.size(), retrans_);
        for (auto &request : handoverQueue_) {
            (void)RetransRequest(ongoingRequests, multi, request);
        }
        handoverQueue_.clear();
        retrans_ = 0;
    } else if (GetStatus() == HttpHandoverHandler::FATAL) {
        NETSTACK_LOGE("Handover status is FATAL, feature disable.");
    }  // LCOV_EXCL_STOP
    return;
}

void HttpHandoverHandler::HandoverTimeoutCallback()
{
    handOverTimerEvent_->ResetEvent();
    handOverTimerEvent_->Stop();
    HandoverQuery();
    if (GetStatus() == HttpHandoverHandler::END) {
        return;
    }
    if (httpHandoverManager_ == nullptr) {
        NETSTACK_LOGE("httpHandoverManager_ nullptr error");
        return;
    }
    httpHandoverReportTimeout_(httpHandoverManager_);  // LCOV_EXCL_LINE
}

int32_t HttpHandoverHandler::IsRequestInQueue(CURL *easyHandle)
{
    time_t sendtime = 0;
    CURLcode result = curl_easy_getinfo(easyHandle, CURLINFO_PRETRANSFER_TIME_T, &sendtime);
    if (result != CURLE_OK) {  // LCOV_EXCL_LINE
        NETSTACK_LOGD("get send time failed:%{public}s", curl_easy_strerror(result));
        return -1;
    }
    return sendtime == 0 ? 1 : 0;
}

int32_t HttpHandoverHandler::IsRequestRead(CURL *easyHandle)
{
    time_t recvtime = 0;
    time_t sendtime = 0;
    return IsRequestRead(easyHandle, recvtime, sendtime);
}

int32_t HttpHandoverHandler::IsRequestRead(CURL *easyHandle, time_t &recvtime, time_t &sendtime)
{
    CURLcode result = curl_easy_getinfo(easyHandle, CURLINFO_STARTTRANSFER_TIME_T, &recvtime);
    if (result != CURLE_OK) {  // LCOV_EXCL_LINE
        NETSTACK_LOGD("get recv time failed:%{public}s", curl_easy_strerror(result));
        return -1;
    }
    result = curl_easy_getinfo(easyHandle, CURLINFO_PRETRANSFER_TIME_T, &sendtime);
    if (result != CURLE_OK) {  // LCOV_EXCL_LINE
        NETSTACK_LOGD("get send time failed:%{public}s", curl_easy_strerror(result));
        return -1;
    }
    return (recvtime == 0 || sendtime == recvtime) ? 0 : 1;
}

bool HttpHandoverHandler::ProcessRequestErr(std::map<CURL *, RequestInfo *> &ongoingRequests,
    CURLM *multi, RequestInfo *requestInfo, CURLMsg *msg)
{
    if (ProcessRequestNetError(ongoingRequests, multi, requestInfo, msg)) {
        return true;
    }
    SetHandoverInfo(requestInfo);
    return false;
}

void HttpHandoverHandler::SetHandoverInfo(RequestInfo *requestInfo)
{
    if (requestInfo == nullptr || requestInfo->opaqueData == nullptr) {
        NETSTACK_LOGE("handover requestInfo nullptr error");
        return;
    }
    HttpHandoverInfo httpHandoverInfo = httpHandoverQueryRequest_(httpHandoverManager_, requestInfo->opaqueData);
    requestInfo->callbacks.setHandoverInfoCallback(httpHandoverInfo, requestInfo->opaqueData);
    DelRequest(requestInfo);
}

bool HttpHandoverHandler::ProcessRequestNetError(std::map<CURL *, RequestInfo *> &ongoingRequests, CURLM *multi,
    RequestInfo *requestInfo, CURLMsg *msg)
{
    if (!requestInfo || requestEndtime_.count(requestInfo) == 0) {
        return false;
    }  // LCOV_EXCL_START
    int endTime = requestEndtime_[requestInfo];
    requestEndtime_.erase(requestInfo);
    if (!msg || !IsNetworkErrorTypeCorrect(msg->data.result)) {
        return false;
    }
    if (!CheckRequestCanRetrans(requestInfo, HandoverRequestType::NETWORKERROR, msg->data.result)) {
        return false;
    }
    if (TryFlowControl(requestInfo, HandoverRequestType::NETWORKERROR)) {
        ++retrans_;
        return true;
    }
    if (endTime == endTime_ - 1) {
        NETSTACK_LOGD("networkerror after end status");
        AddRequest(requestInfo, HandoverRequestType::NETWORKERROR);
        return RetransRequest(ongoingRequests, multi, requestInfo);
    }  // LCOV_EXCL_STOP
    return false;
}

void HttpHandoverHandler::AddRequest(RequestInfo *requestInfo, int32_t type)
{
    if (httpHandoverManager_ == nullptr) {  // LCOV_EXCL_LINE
        NETSTACK_LOGE("httpHandoverManager_ nullptr error");
        return;
    }
    HttpHandoverInfo httpHandoverInfo;
    httpHandoverInfo.handOverReason = type;
    httpHandoverInfo.readFlag = IsRequestRead(requestInfo->easyHandle);
    httpHandoverInfo.inQueueFlag = IsRequestInQueue(requestInfo->easyHandle);
    httpHandoverAddRequest_(httpHandoverManager_, requestInfo->opaqueData, httpHandoverInfo);  // LCOV_EXCL_LINE
}

void HttpHandoverHandler::DelRequest(RequestInfo *requestInfo)
{
    if (httpHandoverManager_ == nullptr) {
        NETSTACK_LOGE("httpHandoverManager_ nullptr error");
        return;
    // LCOV_EXCL_START
    }
    HttpHandoverStackInfo httpHandoverStackInfo = requestInfo->callbacks.handoverInfoCallback(requestInfo->opaqueData);
    httpHandoverDelRequest_(httpHandoverManager_, requestInfo->opaqueData, httpHandoverStackInfo.isSuccess);
    // LCOV_EXCL_STOP
}

int32_t HttpHandoverHandler::GetStatus()
{
    return status_;
}

void HttpHandoverHandler::SetStatus(int32_t status)
{
    status_ = status;
}

int32_t HttpHandoverHandler::GetNetId()
{
    return netId_;
}

void HttpHandoverHandler::SetNetId(int32_t netId)
{
    netId_ = netId;
}
}