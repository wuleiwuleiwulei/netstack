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

#include "napi_utils.h"
#include "netstack_log.h"
#include "context_key.h"
#include "proxy_options.h"

namespace OHOS::NetStack::Socket {

static ProxyType GetProxyType(uint32_t typeId)
{
    if (typeId == 0) {
        return ProxyType::NONE;
    }
    if (typeId == 1) {
        return ProxyType::SOCKS5;
    }
    return ProxyType::UNKNOWN;
}

int ProxyOptions::ParseOptions(napi_env env, napi_value value)
{
    napi_value options = NapiUtils::GetNamedProperty(env, value, KEY_PROXY);
    if (NapiUtils::HasNamedProperty(env, options, KEY_TYPE)) {
        auto typeId = NapiUtils::GetUint32Property(env, options, KEY_TYPE);
        NETSTACK_LOGI("handle proxy type: %{public}d", typeId);

        type_ = GetProxyType(typeId);
        if (type_ == ProxyType::NONE) {
            return 0;
        } else if (type_ == ProxyType::UNKNOWN) {
            NETSTACK_LOGE("invalid proxy type");
            return -1;
        }
    }

    if (!NapiUtils::HasNamedProperty(env, options, KEY_ADDRESS)) {
        NETSTACK_LOGE("proxy options has not address");
        return -1;
    }

    if (NapiUtils::HasNamedProperty(env, options, KEY_USERNAME)) {
        username_ = NapiUtils::GetStringPropertyUtf8(env, options, KEY_USERNAME);
    }
    if (NapiUtils::HasNamedProperty(env, options, KEY_PASSWORD)) {
        password_ = NapiUtils::GetStringPropertyUtf8(env, options, KEY_PASSWORD);
    }

    napi_value netAddress = NapiUtils::GetNamedProperty(env, options, KEY_ADDRESS);
    if (!NapiUtils::HasNamedProperty(env, netAddress, KEY_PORT)) {
        NETSTACK_LOGE("proxy options has not port");
        return -1;
    }

    std::string addr = NapiUtils::GetStringPropertyUtf8(env, netAddress, KEY_ADDRESS);
    if (addr.empty()) {
        NETSTACK_LOGE("proxy options address is empty");
        return -1;
    }

    if (NapiUtils::HasNamedProperty(env, netAddress, KEY_FAMILY)) {
        uint32_t family = NapiUtils::GetUint32Property(env, netAddress, KEY_FAMILY);
        address_.SetFamilyByJsValue(family);
    }

    address_.SetAddress(addr, false);
    if (address_.GetAddress().empty()) {
        NETSTACK_LOGE("proxy options address is invalid");
        return -1;
    }

    uint16_t port = static_cast<uint16_t>(NapiUtils::GetUint32Property(env, netAddress, KEY_PORT));
    address_.SetPort(port);
    return 0;
}
} // namespace OHOS::NetStack::Socket
