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

#include "net_http_request_context.h"

#include <algorithm>

#include "constant.h"
#include "net_http_client_exec.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "net_http_utils.h"

static constexpr const int32_t RESPONSE_MAX_SIZE = 1024 * 1024 * 1024;
static constexpr const uint32_t DNS_SERVER_SIZE = 3;
static constexpr const int32_t PROP_UNSET = -1;
static constexpr size_t PERMISSION_DENIED_CODE = 201;
static constexpr const char *PERMISSION_DENIED_MSG = "Permission denied";
namespace OHOS::NetStack::Http {
static const std::map<int32_t, const char *> HTTP_ERR_MAP = {
    {static_cast<int32_t>(HttpErrorCode::HTTP_UNSUPPORTED_PROTOCOL), "Unsupported protocol."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_URL_MALFORMAT), "Invalid URL format or missing URL."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_COULDNT_RESOLVE_PROXY), "Failed to resolve the proxy name."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_COULDNT_RESOLVE_HOST), "Failed to resolve the host name."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_COULDNT_CONNECT), "Failed to connect to the server."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_WEIRD_SERVER_REPLY), "Invalid server response."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_REMOTE_ACCESS_DENIED), "Access to the remote resource denied."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_HTTP2_ERROR), "Error in the HTTP2 framing layer."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_PARTIAL_FILE), "Transferred a partial file."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_WRITE_ERROR),
        "Failed to write the received data to the disk or application."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_UPLOAD_FAILED), "Upload failed."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_READ_ERROR),
        "Failed to open or read local data from the file or application."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_OUT_OF_MEMORY), "Out of memory."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_OPERATION_TIMEDOUT), "Operation timeout."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_TOO_MANY_REDIRECTS),
        "The number of redirections reaches the maximum allowed."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_GOT_NOTHING), "The server returned nothing (no header or data)."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_SEND_ERROR), "Failed to send data to the peer."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_RECV_ERROR), "Failed to receive data from the peer."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_SSL_CERTPROBLEM), "Local SSL certificate error."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_SSL_CIPHER), "The specified SSL cipher cannot be used."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_PEER_FAILED_VERIFICATION),
        "Invalid SSL peer certificate or SSH remote key."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_BAD_CONTENT_ENCODING),
        "Invalid HTTP encoding format."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_FILESIZE_EXCEEDED), "Maximum file size exceeded."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_REMOTE_DISK_FULL), "Remote disk full."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_REMOTE_FILE_EXISTS), "Remote file already exists."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_SSL_CACERT_BADFILE),
        "The SSL CA certificate does not exist or is inaccessible."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_REMOTE_FILE_NOT_FOUND), "Remote file not found."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_AUTH_ERROR), "Authentication error."},
    {static_cast<int32_t>(HttpErrorCode::HTTP_UNKNOWN_OTHER_ERROR), "Internal error."},
};
RequestContext::RequestContext()
{
    StartTiming();
}

void RequestContext::StartTiming()
{
    time_t startTime = TimeUtils::GetNowTimeMicroseconds();
    timerMap_.RecieveTimer(RESPONSE_HEADER_TIMING).Start(startTime);
    timerMap_.RecieveTimer(RESPONSE_BODY_TIMING).Start(startTime);
    timerMap_.RecieveTimer(RESPONSE_TOTAL_TIMING).Start(startTime);
}

void RequestContext::HandleMethodForGet(CArrUI8 extraData)
{
    if (extraData.head == nullptr) {
        return;
    }
    std::string url = options.GetUrl();
    std::string param;
    auto index = url.find(HTTP_URL_PARAM_START);
    if (index != std::string::npos) {
        param = url.substr(index + 1);
        url.resize(index);
    }
    std::string extraParam{extraData.head, extraData.head + extraData.size};

    options.SetUrl(NetHttpClientExec::MakeUrl(url, param, extraParam));
    return;
}

bool RequestContext::GetRequestBody(CArrUI8 extraData)
{
    /* if body is empty, return false, or curl will wait for body */

    if (extraData.head == nullptr) {
        return false;
    }
    options.SetBody(extraData.head, extraData.size);
    return true;
}

bool RequestContext::IsUsingCache() const
{
    return usingCache_;
}

void RequestContext::SetCurlHeaderList(struct curl_slist *curlHeaderList)
{
    curlHeaderList_ = curlHeaderList;
}

struct curl_slist *RequestContext::GetCurlHeaderList()
{
    return curlHeaderList_;
}
RequestContext::~RequestContext()
{
    if (curlHeaderList_ != nullptr) {
        curl_slist_free_all(curlHeaderList_);
    }
    if (multipart_ != nullptr) {
        curl_mime_free(multipart_);
        multipart_ = nullptr;
    }
    NETSTACK_LOGI("RequestContext is destructed by the destructor");
}

void RequestContext::SetCacheResponse(const HttpResponse &cacheResponse)
{
    cacheResponse_ = cacheResponse;
}
void RequestContext::SetResponseByCache()
{
    response = cacheResponse_;
}

int32_t RequestContext::GetErrorCode() const
{
    if (IsPermissionDenied()) {
        return PERMISSION_DENIED_CODE;
    }

    if (HTTP_ERR_MAP.find(errCode_ + static_cast<int32_t>(HttpErrorCode::HTTP_ERROR_CODE_BASE))
            != HTTP_ERR_MAP.end()) {
        return errCode_ + static_cast<int32_t>(HttpErrorCode::HTTP_ERROR_CODE_BASE);
    }
    return static_cast<int32_t>(HttpErrorCode::HTTP_UNKNOWN_OTHER_ERROR);
}

std::string RequestContext::GetErrorMessage() const
{
    if (IsPermissionDenied()) {
        return PERMISSION_DENIED_MSG;
    }

    auto pos = HTTP_ERR_MAP.find(errCode_ + static_cast<int32_t>(HttpErrorCode::HTTP_ERROR_CODE_BASE));
    if (pos != HTTP_ERR_MAP.end()) {
        return pos->second;
    }
    return HTTP_ERR_MAP.at(static_cast<int32_t>(HttpErrorCode::HTTP_UNKNOWN_OTHER_ERROR));
}

void RequestContext::SetErrorCode(int32_t code)
{
    errCode_ = code;
}

void RequestContext::EnableRequestInStream()
{
    requestInStream_ = true;
}

bool RequestContext::IsRequestInStream() const
{
    return requestInStream_;
}

void RequestContext::SetDlLen(curl_off_t nowLen, curl_off_t totalLen)
{
    std::lock_guard<std::mutex> lock(dlLenLock_);
    LoadBytes dlBytes{nowLen, totalLen};
    dlBytes_.push(dlBytes);
}

void RequestContext::SetUlLen(curl_off_t nowLen, curl_off_t totalLen)
{
    std::lock_guard<std::mutex> lock(ulLenLock_);
    if (!ulBytes_.empty()) {
        ulBytes_.pop();
    }
    LoadBytes ulBytes{nowLen, totalLen};
    ulBytes_.push(ulBytes);
}

LoadBytes RequestContext::GetDlLen()
{
    std::lock_guard<std::mutex> lock(dlLenLock_);
    LoadBytes dlBytes;
    if (!dlBytes_.empty()) {
        dlBytes.nLen = dlBytes_.front().nLen;
        dlBytes.tLen = dlBytes_.front().tLen;
        dlBytes_.pop();
    }
    return dlBytes;
}

LoadBytes RequestContext::GetUlLen()
{
    std::lock_guard<std::mutex> lock(ulLenLock_);
    LoadBytes ulBytes;
    if (!ulBytes_.empty()) {
        ulBytes.nLen = ulBytes_.back().nLen;
        ulBytes.tLen = ulBytes_.back().tLen;
    }
    return ulBytes;
}

bool RequestContext::CompareWithLastElement(curl_off_t nowLen, curl_off_t totalLen)
{
    std::lock_guard<std::mutex> lock(ulLenLock_);
    if (ulBytes_.empty()) {
        return false;
    }
    const LoadBytes &lastElement = ulBytes_.back();
    return nowLen == lastElement.nLen && totalLen == lastElement.tLen;
}

void RequestContext::SetTempData(const void *data, size_t size)
{
    std::lock_guard<std::mutex> lock(tempDataLock_);
    std::string tempString;
    tempString.append(reinterpret_cast<const char *>(data), size);
    tempData_.push(tempString);
}

std::string RequestContext::GetTempData()
{
    std::lock_guard<std::mutex> lock(tempDataLock_);
    if (!tempData_.empty()) {
        return tempData_.front();
    }
    return {};
}

void RequestContext::PopTempData()
{
    std::lock_guard<std::mutex> lock(tempDataLock_);
    if (!tempData_.empty()) {
        tempData_.pop();
    }
}

void RequestContext::CachePerformanceTimingItem(const std::string &key, double value)
{
    performanceTimingMap_[key] = value;
}

void RequestContext::StopAndCachePerformanceTiming(const char *key)
{
    Timer &timer = timerMap_.RecieveTimer(key);
    timer.Stop();
    CachePerformanceTimingItem(key, timer.Elapsed());
}

void RequestContext::SetPerformanceTimingToResult(CHttpResponse &resp)
{
    if (performanceTimingMap_.empty()) {
        NETSTACK_LOGI("Get performanceTiming data is empty.");
        return;
    }

    CPerformanceTiming timing{
        .dnsTiming = performanceTimingMap_[RESPONSE_DNS_TIMING],
        .tcpTiming = performanceTimingMap_[RESPONSE_TCP_TIMING],
        .tlsTiming = performanceTimingMap_[RESPONSE_TLS_TIMING],
        .firstSendTiming = performanceTimingMap_[RESPONSE_FIRST_SEND_TIMING],
        .firstReceiveTiming = performanceTimingMap_[RESPONSE_FIRST_RECEIVE_TIMING],
        .totalFinishTiming = performanceTimingMap_[RESPONSE_TOTAL_FINISH_TIMING],
        .redirectTiming = performanceTimingMap_[RESPONSE_REDIRECT_TIMING],
        .responseHeaderTiming = performanceTimingMap_[RESPONSE_HEADER_TIMING],
        .responseBodyTiming = performanceTimingMap_[RESPONSE_BODY_TIMING],
        .totalTiming = performanceTimingMap_[RESPONSE_TOTAL_TIMING]
    };
    resp.performanceTiming = timing;
}

void RequestContext::SetMultipart(curl_mime *multipart)
{
    multipart_ = multipart;
}

void RequestContext::SetParseOK()
{
    parseok_ = true;
}

bool RequestContext::IsParseOK() const
{
    return parseok_;
}

void RequestContext::SetExecOK(bool ok)
{
    requestOK_ = ok;
}

bool RequestContext::IsExecOK() const
{
    return requestOK_;
}

void RequestContext::SetPermissionDenied(bool deny)
{
    permissionDenied_ = deny;
}

bool RequestContext::IsPermissionDenied() const
{
    return permissionDenied_;
}

void RequestContext::Destroy()
{
    isDestroyed_ = true;
}

bool RequestContext::IsDestroyed() const
{
    return isDestroyed_;
}

bool RequestContext::IsRootCaVerified() const
{
    return isRootCaVerified_;
}

void RequestContext::SetRootCaVerified()
{
    isRootCaVerified_ = true;
}

bool RequestContext::IsRootCaVerifiedOk() const
{
    return isRootCaVerifiedOk_;
}

void RequestContext::SetRootCaVerifiedOk(bool ok)
{
    isRootCaVerifiedOk_ = ok;
}

void RequestContext::SetPinnedPubkey(std::string &pubkey)
{
    pinnedPubkey_ = pubkey;
}

std::string RequestContext::GetPinnedPubkey() const
{
    return pinnedPubkey_;
}

void RequestContext::SetCertsPath(std::vector<std::string> &&certPathList, const std::string &certFile)
{
    certsPath_.certPathList = std::move(certPathList);
    certsPath_.certFile = certFile;
}

const CertsPath &RequestContext::GetCertsPath()
{
    return certsPath_;
}

void RequestContext::ParseParams(std::string url, CHttpRequestOptions *ops)
{
    options.SetUrl(url);
    if (ops != nullptr) {
        options.SetMethod(std::string(ops->method));
        options.SetReadTimeout(ops->readTimeout);
        options.SetMaxLimit(ops->maxLimit);
        options.SetConnectTimeout(ops->connectTimeout);
        usingCache_ = ops->usingCache;
        if (ops->usingProtocol == static_cast<int32_t>(HttpProtocol::HTTP1_1) ||
            ops->usingProtocol == static_cast<int32_t>(HttpProtocol::HTTP2)) {
                options.SetUsingProtocol(static_cast<HttpProtocol>(ops->usingProtocol));
            }
        if (ops->expectDataType != PROP_UNSET) {
            options.SetHttpDataType(static_cast<HttpDataType>(ops->expectDataType));
        }
        options.SetPriority(ops->priority);
        ParseUsingHttpProxy(ops->usingProxy, ops->usingDefaultProxy);
        if (ops->clientCert != nullptr) {
            std::string certPath{ops->clientCert->certPath};
            std::string certType{ops->clientCert->certType};
            std::string keyPath{ops->clientCert->keyPath};
            SecureChar keyPasswd;
            if (ops->clientCert->keyPassword != nullptr) {
                keyPasswd = SecureChar(ops->clientCert->keyPassword);
            } else {
                keyPasswd = SecureChar("");
            }
            options.SetClientCert(certPath, certType, keyPath, keyPasswd);
        }
        if (!ParseExtraData(ops->extraData)) {
            return;
        }
        ParseHeader(ops->header);
        if (ops->caPath != nullptr) {
            options.SetCaPath(std::string{ops->caPath});
        }
        if (ops->dnsOverHttps != nullptr) {
            options.SetDohUrl(std::string{ops->dnsOverHttps});
        }
        options.SetRangeNumber(ops->resumeFrom, ops->resumeTo);
        ParseDnsServers(ops->dnsServer);
        ParseMultiFormData(ops->multiFormDataList);
    }
    SetParseOK();
}

void RequestContext::ParseUsingHttpProxy(CHttpProxy* proxy, bool useDefault)
{
    if (proxy != nullptr) {
        options.SetUsingHttpProxyType(UsingHttpProxyType::USE_SPECIFIED);
        std::string host{proxy->host};
        std::string exclusionList;
        for (int i = 0; i < proxy->exclusionListSize; i++) {
            if (i != 0) {
                exclusionList = exclusionList + HTTP_PROXY_EXCLUSIONS_SEPARATOR;
            }
            exclusionList += std::string{proxy->exclusionList[i]};
        }
        options.SetSpecifiedHttpProxy(host, proxy->port, exclusionList);
    } else {
        UsingHttpProxyType usingType = useDefault ? UsingHttpProxyType::USE_DEFAULT : UsingHttpProxyType::NOT_USE;
        options.SetUsingHttpProxyType(usingType);
    }
}

void RequestContext::ParseHeader(CArrString header)
{
    if (header.head == nullptr || header.size == 0) {
        return;
    }
    if (NetHttpClientExec::MethodForPost(options.GetMethod())) {
        options.SetHeader(CommonUtils::ToLower(HTTP_CONTENT_TYPE), HTTP_CONTENT_TYPE_JSON); // default
    }
    for (int i = 0; i < header.size; i += MAP_TUPLE_SIZE) {
        std::string key{header.head[i]};
        std::string value{header.head[i + 1]};
        options.SetHeader(CommonUtils::ToLower(key), value);
    }
}

void RequestContext::ParseDnsServers(CArrString dns)
{
    if (dns.size == 0) {
        return;
    }
    std::vector<std::string> dnsServers;
    uint32_t dnsSize = 0;
    for (uint32_t i = 0; i < dns.size && dnsSize < DNS_SERVER_SIZE; i++) {
        std::string dnsServer{dns.head[i]};
        if (dnsServer.empty()) {
            continue;
        }
        if (!CommonUtils::IsValidIPV4(dnsServer) && !CommonUtils::IsValidIPV6(dnsServer)) {
            continue;
        }
        dnsServers.push_back(dnsServer);
        dnsSize++;
    }
    options.SetDnsServers(dnsServers);
}

bool RequestContext::ParseExtraData(CArrUI8 data)
{
    if (data.size == 0) {
        return true;
    }
    if (NetHttpClientExec::MethodForGet(options.GetMethod())) {
        HandleMethodForGet(data);
        return true;
    }

    if (NetHttpClientExec::MethodForPost(options.GetMethod())) {
        return GetRequestBody(data);
    }
    return false;
}

void RequestContext::ParseMultiFormData(CArrMultiFormData multi)
{
    if (multi.size == 0) {
        return;
    }

    for (int i = 0; i < multi.size; i++) {
        CMultiFormData from = multi.data[i];
        MultiFormData multiFormData;
        multiFormData.name = std::string{from.name};
        multiFormData.contentType = std::string{from.contentType};
        if (from.remoteFileName != nullptr) {
            multiFormData.remoteFileName = std::string{from.remoteFileName};
        }
        if (from.filePath != nullptr) {
            multiFormData.filePath = std::string{from.filePath};
        }
        if (from.data.size > 0) {
            std::string data{from.data.head, from.data.head + from.data.size};
            multiFormData.data = data;
        }
        options.AddMultiFormData(multiFormData);
    }
}

void ParseSetCookie(CArrString &setCookie, HttpResponse &response)
{
    auto setCookieSize = response.GetsetCookie().size();
    if (setCookieSize > 0 && setCookieSize < RESPONSE_MAX_SIZE) {
        setCookie.head = static_cast<char**>(malloc(sizeof(char*) * setCookieSize));
        if (setCookie.head == nullptr) {
            return;
        }
        setCookie.size = static_cast<int64_t>(setCookieSize);
        int i = 0;
        for (const auto &cookie : response.GetsetCookie()) {
            setCookie.head[i] = MallocCString(cookie);
            i++;
        }
    }
}

void RequestContext::SendResponse()
{
    CHttpResponse resp = { .errCode = 0,
        .errMsg = nullptr,
        .result = { .head = nullptr, .size = 0},
        .resultType = 2,
        .responseCode = 0,
        .header = CArrString{ .head = nullptr, .size = 0 },
        .cookies = nullptr,
        .setCookie = CArrString{ .head = nullptr, .size = 0 },
        .performanceTiming = CPerformanceTiming{}};
    if (IsExecOK()) {
        resp.responseCode = response.GetResponseCode();
        if (!IsRequestInStream()) {
            auto headerSize = response.GetHeader().size();
            resp.cookies = MallocCString(response.GetCookies());
            if (headerSize > 0) {
                resp.header = g_map2CArrString(response.GetHeader());
            }
            ParseSetCookie(resp.setCookie, response);
            StopAndCachePerformanceTiming(RESPONSE_TOTAL_TIMING);
            SetPerformanceTimingToResult(resp);
            resp.result.head = reinterpret_cast<uint8_t*>(MallocCString(response.GetResult()));
            resp.result.size = static_cast<int64_t>(response.GetResult().length());
            resp.resultType = static_cast<int32_t>(options.GetHttpDataType());
        }
    } else {
        resp.errCode = GetErrorCode();
        resp.errMsg = MallocCString(GetErrorMessage());
    }
    respCallback(resp);
}

RequestContext* HttpRequestProxy::Request(std::string url, CHttpRequestOptions *ops, bool isInStream)
{
    if (!NetHttpClientExec::Initialize()) {
        return nullptr;
    }

    RequestContext* context = new RequestContext();
    if (context == nullptr) {
        return nullptr;
    }
    if (!CommonUtils::HasInternetPermission()) {
        context->SetPermissionDenied(true);
        return context;
    }
    context->options.SetRequestTime(GetNowTimeGMT());
    if (isInStream) {
        context->EnableRequestInStream();
    }
    context->ParseParams(url, ops);

    if (!context->IsParseOK()) {
        // context.setxxx
        return context;
    }
    NetHttpClientExec::ExecRequest(context);
    return context;
}

void HttpRequestProxy::Destroy()
{
    isDestroyed = true;

    // clear funcs
    callbacks->headersReceive.clear();
    callbacks->headersReceiveOnce.clear();
    callbacks->dataReceive.clear();
    callbacks->dataEnd.clear();
    callbacks->dataReceiveProgress.clear();
    callbacks->dataSendProgress.clear();
}

} // namespace OHOS::NetStack::Http
