/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "netstack_chr_client.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "i_netstack_chr_client.h"

namespace OHOS::NetStack::ChrClient {

static constexpr const long HTTP_REQUEST_SUCCESS_MIN = 200;
static constexpr const long HTTP_REQUEST_SUCCESS_MAX = 299;
static constexpr const int HTTP_FILE_TRANSFER_SIZE_THRESHOLD = 100000;
static constexpr const int HTTP_FILE_TRANSFER_TIME_THRESHOLD = 500000;

NetStackChrClient &NetStackChrClient::GetInstance()
{
    static NetStackChrClient instance;
    return instance;
}

int NetStackChrClient::GetAddrFromSock(int sockfd, struct DataTransTcpInfo &httpTcpInfo)
{
    sockaddr_storage localss{};
    sockaddr_storage peerss{};
    socklen_t addrLen = 0;

    // Get local addr
    addrLen = sizeof(localss);
    (void)getsockname(sockfd, reinterpret_cast<sockaddr *>(&localss), &addrLen);

    // Get peer addr
    addrLen = sizeof(peerss);
   (void)getpeername(sockfd, reinterpret_cast<sockaddr *>(&peerss), &addrLen);

    char buf[INET6_ADDRSTRLEN] = {0};
    httpTcpInfo.ipType = localss.ss_family;
    if (localss.ss_family == AF_INET && peerss.ss_family == AF_INET) {
        auto *l4 = reinterpret_cast<sockaddr_in *>(&localss);
        auto *p4 = reinterpret_cast<sockaddr_in *>(&peerss);
        if (inet_ntop(AF_INET, &l4->sin_addr, buf, sizeof(buf)) != nullptr) {
            httpTcpInfo.srcIp = buf;
            httpTcpInfo.srcPort = ntohs(l4->sin_port);
        }
        if (inet_ntop(AF_INET, &p4->sin_addr, buf, sizeof(buf)) != nullptr) {
            httpTcpInfo.dstIp = buf;
            httpTcpInfo.dstPort = ntohs(p4->sin_port);
        }
    } else if (localss.ss_family == AF_INET6 && peerss.ss_family == AF_INET6) {
        auto *l6 = reinterpret_cast<sockaddr_in6 *>(&localss);
        auto *p6 = reinterpret_cast<sockaddr_in6 *>(&peerss);
        if (inet_ntop(AF_INET6, &l6->sin6_addr, buf, sizeof(buf)) != nullptr) {
            httpTcpInfo.srcIp = buf;
            httpTcpInfo.srcPort = ntohs(l6->sin6_port);
        }
        if (inet_ntop(AF_INET6, &p6->sin6_addr, buf, sizeof(buf)) != nullptr) {
            httpTcpInfo.dstIp = buf;
            httpTcpInfo.dstPort = ntohs(p6->sin6_port);
        }
    } else {
        return -1;
    }
    
    return 0;
}

int NetStackChrClient::GetTcpInfoFromSock(const curl_socket_t sockfd, DataTransTcpInfo &httpTcpInfo)
{
    if (sockfd <= 0) {
        return -1;
    }
    struct tcp_info tcpInfo = {};
    socklen_t infoLen = sizeof(tcpInfo);

    if (getsockopt(sockfd, IPPROTO_TCP, TCP_INFO, &tcpInfo, &infoLen) < 0) {
        return -1;
    }

    httpTcpInfo.unacked = tcpInfo.tcpi_unacked;
    httpTcpInfo.lastDataSent = tcpInfo.tcpi_last_data_sent;
    httpTcpInfo.lastAckSent = tcpInfo.tcpi_last_ack_sent;
    httpTcpInfo.lastDataRecv = tcpInfo.tcpi_last_data_recv;
    httpTcpInfo.lastAckRecv = tcpInfo.tcpi_last_ack_recv;
    httpTcpInfo.rtt = tcpInfo.tcpi_rtt;
    httpTcpInfo.rttvar = tcpInfo.tcpi_rttvar;
    httpTcpInfo.totalRetrans = tcpInfo.tcpi_total_retrans;
    httpTcpInfo.retransmits = tcpInfo.tcpi_retransmits;

    if (GetAddrFromSock(sockfd, httpTcpInfo) == 0) {
        httpTcpInfo.srcIp = CommonUtils::AnonymizeIp(httpTcpInfo.srcIp);
        httpTcpInfo.dstIp = CommonUtils::AnonymizeIp(httpTcpInfo.dstIp);
    }

    return 0;
}

template <typename DataType>
DataType NetStackChrClient::GetNumericAttributeFromCurl(CURL *handle, CURLINFO info)
{
    DataType number = 0;
    CURLcode res = curl_easy_getinfo(handle, info, &number);
    if (res != CURLE_OK) {
        return -1;
    }
    return number;
}

std::string NetStackChrClient::GetStringAttributeFromCurl(CURL *handle, CURLINFO info)
{
    char *result = nullptr;
    CURLcode res = curl_easy_getinfo(handle, info, &result);
    if (res != CURLE_OK || result == nullptr) {
        return std::string();
    }
    return std::string(result);
}

long NetStackChrClient::GetRequestStartTime(curl_off_t totalTime)
{
    auto now = std::chrono::system_clock::now();
    long msCount = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    return msCount;
}

void NetStackChrClient::GetHttpInfoFromCurl(CURL *handle, DataTransHttpInfo &httpInfo)
{
    (void)curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &httpInfo.responseCode);
    httpInfo.nameLookUpTime = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_NAMELOOKUP_TIME_T);
    httpInfo.connectTime = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_CONNECT_TIME_T);
    httpInfo.preTransferTime = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_PRETRANSFER_TIME_T);
    httpInfo.startTransferTime = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_STARTTRANSFER_TIME_T);
    httpInfo.totalTime = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_TOTAL_TIME_T);
    httpInfo.redirectTime = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_REDIRECT_TIME_T);
    httpInfo.appconnectTime = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_APPCONNECT_TIME_T);
    httpInfo.queueTime = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_QUEUE_TIME_T);
    httpInfo.retryAfter = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_RETRY_AFTER);
    httpInfo.requestStartTime = GetRequestStartTime(httpInfo.totalTime);

    httpInfo.sizeUpload = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_SIZE_UPLOAD_T);
    httpInfo.sizeDownload = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_SIZE_DOWNLOAD_T);
    httpInfo.speedDownload = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_SPEED_DOWNLOAD_T);
    httpInfo.speedUpload = GetNumericAttributeFromCurl<curl_off_t>(handle, CURLINFO_SPEED_UPLOAD_T);

    httpInfo.redirectCount = GetNumericAttributeFromCurl<long>(handle, CURLINFO_REDIRECT_COUNT);
    httpInfo.osError = GetNumericAttributeFromCurl<long>(handle, CURLINFO_OS_ERRNO);
    httpInfo.sslVerifyResult = GetNumericAttributeFromCurl<long>(handle, CURLINFO_PROXY_SSL_VERIFYRESULT);
    httpInfo.proxyError = GetNumericAttributeFromCurl<long>(handle, CURLINFO_PROXY_ERROR);

    httpInfo.effectiveMethod = GetStringAttributeFromCurl(handle, CURLINFO_EFFECTIVE_METHOD);
    httpInfo.contentType = GetStringAttributeFromCurl(handle, CURLINFO_CONTENT_TYPE);
}

int NetStackChrClient::ShouldReportHttpAbnormalEvent(const DataTransHttpInfo &httpInfo)
{
    if (httpInfo.responseCode < HTTP_REQUEST_SUCCESS_MIN || httpInfo.responseCode > HTTP_REQUEST_SUCCESS_MAX ||
        httpInfo.curlCode != 0 || httpInfo.osError != 0 || httpInfo.proxyError != 0) {
        return 0;
    }
    if ((httpInfo.sizeUpload + httpInfo.sizeDownload <= HTTP_FILE_TRANSFER_SIZE_THRESHOLD) &&
        httpInfo.totalTime > HTTP_FILE_TRANSFER_TIME_THRESHOLD) {
        return 0;
    }

    return -1;
}

void NetStackChrClient::GetDfxInfoFromCurlHandleAndReport(CURL *handle, int32_t curlCode)
{
    if (handle == NULL) {
        return;
    }

    DataTransChrStats dataTransChrStats{};
    dataTransChrStats.httpInfo.uid = static_cast<int>(getuid());
    dataTransChrStats.httpInfo.curlCode = curlCode;
    if (CommonUtils::GetBundleName().has_value()) {
        dataTransChrStats.processName = CommonUtils::GetBundleName().value();
    }

    GetHttpInfoFromCurl(handle, dataTransChrStats.httpInfo);
    if (ShouldReportHttpAbnormalEvent(dataTransChrStats.httpInfo) != 0) {
        return;
    }

    curl_off_t sockfd = 0;
    curl_easy_getinfo(handle, CURLINFO_ACTIVESOCKET, &sockfd);

    if (GetTcpInfoFromSock(sockfd, dataTransChrStats.tcpInfo) != 0) {
        NETSTACK_LOGE("Chr client get tcp info from socket failed, sockfd: %{public} " PRId64, sockfd);
        return;
    }

    int ret = netstackChrReport_.ReportCommonEvent(dataTransChrStats);
    if (ret > 0) {
        NETSTACK_LOGE("Send to CHR failed, error code %{public}d", ret);
    }
}

}  // namespace OHOS::NetStack::ChrClient