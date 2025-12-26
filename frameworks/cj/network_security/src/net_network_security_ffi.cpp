/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include "net_network_security_ffi.h"
#include "net_ssl.h"

using namespace OHOS::NetStack::Ssl;
namespace OHOS::NetStack::NetworkSecurity {
extern "C" {
int64_t FfiOHOSNetworkSecurityCertVerificationCert(CCertBlob cert)
{
    CertBlob certBlob = CertBlob{ static_cast<CertType>(cert.certType),
        static_cast<uint32_t>(cert.certData.size), cert.certData.head };
    uint32_t ret = NetStackVerifyCertification(&certBlob);
    return static_cast<int64_t>(ret);
}

int64_t FfiOHOSNetworkSecurityCertVerificationCaCert(CCertBlob cert, CCertBlob caCert)
{
    CertBlob certBlob = CertBlob{ static_cast<CertType>(cert.certType),
        static_cast<uint32_t>(cert.certData.size), cert.certData.head };
    CertBlob caCertBlob = CertBlob{ static_cast<CertType>(caCert.certType),
        static_cast<uint32_t>(caCert.certData.size), caCert.certData.head };
    uint32_t ret = NetStackVerifyCertification(&certBlob, &caCertBlob);
    return static_cast<int64_t>(ret);
}
}
} // namespace OHOS::NetStack::NetworkSecurity