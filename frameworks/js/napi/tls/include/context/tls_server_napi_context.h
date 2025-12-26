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

#ifndef TLS_CONTEXT_SERVER_NAPI_CONTEXT_H
#define TLS_CONTEXT_SERVER_NAPI_CONTEXT_H

#include <cstddef>
#include <string>
#include <vector>

#include <napi/native_api.h>

#include "base_context.h"
#include "event_manager.h"
#include "net_address.h"
#include "socket_state_base.h"
#include "tls.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
class TLSServerNapiContext final : public BaseContext {
public:
    TLSServerNapiContext() = delete;
    explicit TLSServerNapiContext(napi_env env, const std::shared_ptr<EventManager> &manager);

public:
    int32_t clientId_ = 0;
    int32_t errorNumber_ = 0;
    int32_t socketFd_ = -1;
    Socket::NetAddress address_;
    Socket::NetAddress localAddress_;
    TlsSocket::X509CertRawData remoteCert_;
    std::vector<std::string> cipherSuites_;
    std::vector<std::string> signatureAlgorithms_;

public:
    void ParseParams(napi_value *params, size_t paramsCount);

private:
    bool CheckParamsType(napi_value *params, size_t paramsCount);
};

using ServerTLSGetRemoteAddressContext = TLSServerNapiContext;
using TLSServerGetLocalAddressContext = TLSServerNapiContext;
using TLSConnectionGetLocalAddressContext = TLSServerNapiContext;
using ServerGetRemoteCertificateContext = TLSServerNapiContext;
using ServerGetCipherSuitesContext = TLSServerNapiContext;
using ServerGetSignatureAlgorithmsContext = TLSServerNapiContext;
using TLSServerGetSocketFdContext = TLSServerNapiContext;
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
#endif // TLS_CONTEXT_SERVER_NAPI_CONTEXT_H
