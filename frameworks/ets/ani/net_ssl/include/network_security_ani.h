/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NET_NETWORK_SECURITY_ANI_H
#define NET_NETWORK_SECURITY_ANI_H

#include <cstdint>
#include <string>
#include "cxx.h"
#include "net_conn_client.h"
#include "network_security_config.h"
#include "net_ssl.h"

namespace OHOS {

namespace NetStackAni {
struct CertBlob;

inline int32_t IsCleartextPermitted(bool &isCleartextPermitted)
{
    return NetManagerStandard::NetworkSecurityConfig::GetInstance().IsCleartextPermitted(isCleartextPermitted);
}

inline int32_t IsCleartextPermittedByHostName(std::string const &hostName, bool &isCleartextPermitted)
{
    return NetManagerStandard::NetworkSecurityConfig::GetInstance()
           .IsCleartextPermitted(hostName, isCleartextPermitted);
}

uint32_t NetStackVerifyCertificationCa(const CertBlob &cert, const CertBlob &caCert);
uint32_t NetStackVerifyCertification(const CertBlob &cert);
rust::String GetErrorCodeAndMessage(int32_t &errorCode);

} // namespace NetStackAni
} // namespace OHOS

#endif // NET_NETWORK_SECURITY_ANI_H