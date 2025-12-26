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

#include "socks5_none_method.h"

#include "netstack_log.h"
#include "socks5_utils.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {
bool Socks5NoneMethod::RequestAuth(std::int32_t socketId, const std::string &userName, const std::string &password,
    const Socks5ProxyAddress &proxy)
{
    static_cast<void>(socketId);
    static_cast<void>(userName);
    static_cast<void>(password);
    static_cast<void>(proxy);
    return true;
}

std::pair<bool, Socks5ProxyResponse> Socks5NoneMethod::RequestProxy(std::int32_t socketId, Socks5Command command,
    const Socket::NetAddress &destAddr, const Socks5ProxyAddress &proxy)
{
    const Socket::NetAddress::Family family{destAddr.GetFamily()};
    Socks5AddrType addrType;
    if (family == Socket::NetAddress::Family::IPv4) {
        addrType = Socks5AddrType::IPV4;
    } else if (family == Socket::NetAddress::Family::IPv6) {
        addrType = Socks5AddrType::IPV6;
    } else {
        addrType = Socks5AddrType::DOMAIN_NAME;
    }

    Socks5ProxyRequest request{};
    request.version_ = SOCKS5_VERSION;
    request.cmd_ = command;
    request.reserved_ = 0U;
    request.addrType_ = addrType;
    request.destAddr_ = destAddr.GetAddress();
    request.destPort_ = destAddr.GetPort();

    const socklen_t addrLen{Socks5Utils::GetAddressLen(proxy.netAddress_)};
    const std::pair<sockaddr *, socklen_t> addrInfo{proxy.addr_, addrLen};
    Socks5ProxyResponse response{};
    if (!Socks5Utils::RequestProxyServer(GetSocks5Instance(), socketId, addrInfo, &request, &response)) {
        NETSTACK_LOGE("RequestProxy failed, socket is %{public}d", socketId);
        return {false, response};
    }
    if (response.status_ != static_cast<uint8_t>(Socks5Status::SUCCESS)) {
        GetSocks5Instance()->UpdateErrorInfo(Socks5Status::SOCKS5_FAIL_TO_CONNECT_REMOTE);
        NETSTACK_LOGE("socks5 fail to request proxy, socket is %{public}d", socketId);
        return {false, response};
    }
    return {true, response};
}

} // Socks5
} // NetStack
} // OHOS
