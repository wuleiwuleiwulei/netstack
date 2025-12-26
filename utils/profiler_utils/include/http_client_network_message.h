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

#ifndef NETSTACK_HTTP_CLIENT_NETWORK_MESSAGE_H
#define NETSTACK_HTTP_CLIENT_NETWORK_MESSAGE_H

#include "i_network_message.h"
#include "http_client_request.h"
#include "http_client_response.h"

namespace OHOS::NetStack {
class HttpClientNetworkMessage : public INetworkMessage {
public:
    HttpClientNetworkMessage() = delete;
#if HAS_NETMANAGER_BASE
    HttpClientNetworkMessage(std::string requestId, HttpClient::HttpClientRequest &request,
                             HttpClient::HttpClientResponse &response, CURL *handle);
#endif
    ~HttpClientNetworkMessage() override;
    DfxMessage Parse() override;

private:
#if HAS_NETMANAGER_BASE
    CURL *handle_ = nullptr;
#endif
    TimeInfo timeInfo_;
    HttpClient::HttpClientRequest request_;
    HttpClient::HttpClientResponse response_;
};
}

#endif //NETSTACK_HTTP_CLIENT_NETWORK_MESSAGE_H
