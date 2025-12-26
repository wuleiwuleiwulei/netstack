/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATION_NETSTACK_TLS_CONTEXT_SERVER_H
#define COMMUNICATION_NETSTACK_TLS_CONTEXT_SERVER_H

#include <memory>

#include "tls.h"
#include "tls_configuration.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
class TLSContextServer {
public:
    TLSContextServer() = default;
    ~TLSContextServer() = default;
    static std::unique_ptr<TLSContextServer> CreateConfiguration(const TLSConfiguration &configuration);
    SSL *CreateSsl();
    void CloseCtx();

private:
    static bool InitTlsContext(TLSContextServer *sslContext, const TLSConfiguration &configuration);
    static bool SetCipherList(TLSContextServer *tlsContext, const TLSConfiguration &configuration);
    static bool SetSignatureAlgorithms(TLSContextServer *tlsContext, const TLSConfiguration &configuration);
    static void GetCiphers(TLSContextServer *tlsContext);
    static void UseRemoteCipher(TLSContextServer *tlsContext);
    static void SetMinAndMaxProtocol(TLSContextServer *tlsContext);
    static bool SetDefaultCa(TLSContextServer *tlsContext, const TLSConfiguration &configuration);
    static bool SetCaAndVerify(TLSContextServer *tlsContext, const TLSConfiguration &configuration);
    static bool SetLocalCertificate(TLSContextServer *tlsContext, const TLSConfiguration &configuration);
    static bool SetKeyAndCheck(TLSContextServer *tlsContext, const TLSConfiguration &configuration);
    static void SetVerify(TLSContextServer *tlsContext);

private:
    SSL_CTX *ctx_ = nullptr;
    EVP_PKEY *pkey_ = nullptr;
    SSL *ctxSsl_ = nullptr;
    TLSConfiguration tlsConfiguration_;
    static VerifyMode verifyMode_;
};
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
#endif // COMMUNICATION_NETSTACK_TLS_CONTEXT_H
