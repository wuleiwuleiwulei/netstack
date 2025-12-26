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

#include <iostream>

#include "net_ssl.h"
#include "net_ssl_verify_cert.h"
#include "netstack_log.h"

namespace OHOS {
namespace NetStack {
namespace Ssl {
uint32_t NetStackVerifyCertification(const CertBlob *cert)
{
    if (cert == nullptr) {
        NETSTACK_LOGE("input error:nullptr\n");
    }

    return VerifyCert(cert);
}

uint32_t NetStackVerifyCertification(const CertBlob *cert, const CertBlob *caCert)
{
    if (cert == nullptr || caCert == nullptr) {
        NETSTACK_LOGE("input error:nullptr\n");
    }

    return VerifyCert(cert, caCert);
}
} // namespace Ssl
} // namespace NetStack
} // namespace OHOS
