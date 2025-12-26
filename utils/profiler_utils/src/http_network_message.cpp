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

#include "http_network_message.h"

namespace OHOS::NetStack {
namespace {
#if HAS_NETMANAGER_BASE
constexpr const size_t RESPONSE_BODY_MAX_SIZE = 64 * 1024;
#endif
}

#if HAS_NETMANAGER_BASE
HttpNetworkMessage::HttpNetworkMessage(std::string requestId, Http::HttpRequestOptions &request,
                                       Http::HttpResponse &response, CURL *handle)
    : INetworkMessage(std::move(requestId)),
      handle_(handle),
      request_(request),
      response_(response) {}
#endif

HttpNetworkMessage::~HttpNetworkMessage() = default;

DfxMessage HttpNetworkMessage::Parse()
{
    DfxMessage msg{};
#if HAS_NETMANAGER_BASE
    GetTimeInfoFromCurlHandle(timeInfo_, handle_);
    msg.requestBeginTime_ = requestBeginTime_;
    msg.dnsEndTime_ = msg.requestBeginTime_ + static_cast<uint64_t>(timeInfo_.dnsTime);
    msg.tcpConnectEndTime_ =
            msg.dnsEndTime_ + static_cast<uint64_t>(std::max(0.0, timeInfo_.tcpConnectTime - timeInfo_.dnsTime));
    msg.tlsHandshakeEndTime_ = msg.tcpConnectEndTime_ +
                               static_cast<uint64_t>(std::max(0.0, timeInfo_.tlsHandshakeTime -
                                                                   timeInfo_.tcpConnectTime));
    msg.firstSendTime_ = msg.tlsHandshakeEndTime_ +
                         static_cast<uint64_t>(std::max(0.0, timeInfo_.firstSendTime -
                                                             std::max({timeInfo_.dnsTime,
                                                                       timeInfo_.tcpConnectTime,
                                                                       timeInfo_.tlsHandshakeTime})));
    msg.firstRecvTime_ = msg.firstSendTime_ +
                         static_cast<uint64_t>(std::max(0.0, timeInfo_.firstRecvTime - timeInfo_.firstSendTime));
    msg.requestEndTime_ = msg.firstRecvTime_ + static_cast<uint64_t>(timeInfo_.totalTime - timeInfo_.firstRecvTime);
    msg.requestId_ = requestId_;
    msg.requestUrl_ = request_.GetUrl();
    msg.requestMethod_ = request_.GetMethod();
    msg.requestHeader_ = GetRawHeader(request_.GetHeader());
    msg.responseStatusCode_ = response_.GetResponseCode();
    msg.responseHeader_ = response_.GetRawHeader();
    msg.responseReasonPhrase_ = GetReasonParse(response_.GetRawHeader());
    if (response_.GetResult().size() > RESPONSE_BODY_MAX_SIZE) {
        msg.responseBody_ = response_.GetResult().substr(0, RESPONSE_BODY_MAX_SIZE);
    } else {
        msg.responseBody_ = response_.GetResult();
    }
    GetIpAddressFromCurlHandle(msg.responseIpAddress_, handle_);
    GetEffectiveUrlFromCurlHandle(msg.responseEffectiveUrl_, handle_);
    GetHttpVersionFromCurlHandle(msg.responseHttpVersion_, handle_);
#endif
    return msg;
}
}