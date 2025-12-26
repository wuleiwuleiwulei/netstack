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

#include "socks5_passwd_method.h"

#include "netstack_log.h"
#include "socks5_utils.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {
bool Socks5PasswdMethod::RequestAuth(std::int32_t socketId, const std::string &username,
    const std::string &password, const Socks5ProxyAddress &proxy)
{
    if (username.empty() || password.empty()) {
        GetSocks5Instance()->UpdateErrorInfo(Socks5Status::SOCKS5_USER_PASS_INVALID);
        NETSTACK_LOGE("socks5 username or password is empty, socket is %{public}d", socketId);
        return false;
    }

    Socks5AuthRequest request{};
    request.version_ = SOCKS5_SUBVERSION;
    request.username_ = username;
    request.password_ = password;

    const socklen_t addrLen{Socks5Utils::GetAddressLen(proxy.netAddress_)};
    const std::pair<sockaddr *, socklen_t> addrInfo{proxy.addr_, addrLen};
    Socks5AuthResponse response{};
    if (!Socks5Utils::RequestProxyServer(GetSocks5Instance(), socketId, addrInfo, &request, &response)) {
        NETSTACK_LOGE("RequestProxy failed, socket is %{public}d", socketId);
        return false;
    }
    if (response.status_ != static_cast<uint8_t>(Socks5Status::SUCCESS)) {
        GetSocks5Instance()->UpdateErrorInfo(Socks5Status::SOCKS5_USER_PASS_INVALID);
        NETSTACK_LOGE("socks5 fail to request auth, socket is %{public}d", socketId);
        return false;
    }
    return true;
}

} // Socks5
} // NetStack
} // OHOS
