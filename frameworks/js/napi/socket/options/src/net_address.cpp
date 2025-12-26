/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <netdb.h>

#include "net_address.h"
#include "netstack_log.h"
#include "socket_exec_common.h"
#include "securec.h"

namespace OHOS::NetStack::Socket {

NetAddress::NetAddress() : family_(Family::IPv4), port_(0) {}

NetAddress::NetAddress(const NetAddress &other) : address_(other.address_), family_(other.family_), port_(other.port_)
{
}

void NetAddress::SetIpAddress(const std::string &address)
{
    if (address.empty()) {
        return;
    }
    if (address == "localhost") {
        if (family_ == Family::IPv4) {
            address_ = ConvertAddressToIp(address, AF_INET);
        } else if (family_ == Family::IPv6) {
            address_ = ConvertAddressToIp(address, AF_INET6);
        }
        return;
    }
    if (family_ == Family::IPv4) {
        in6_addr ipv6{};
        if (inet_pton(AF_INET6, address.c_str(), &ipv6) > 0) {
            return;
        }
        auto pos = address.find('%');
        if (pos != std::string::npos) {
            auto subAddr = address.substr(0, pos);
            in6_addr newIpv6{};
            if (inet_pton(AF_INET6, subAddr.c_str(), &newIpv6) > 0) {
                return;
            }
        }
        in_addr ipv4{};
        if (inet_pton(AF_INET, address.c_str(), &(ipv4.s_addr)) > 0) {
            address_ = address;
            return;
        }
    } else {
        in6_addr ipv6{};
        if (inet_pton(AF_INET6, address.c_str(), &ipv6) > 0) {
            address_ = address;
            return;
        }
    }
    SetIpAddressInner(address);
}

void NetAddress::SetIpAddressInner(const std::string &address)
{
    if (family_ == Family::IPv4) {
        constexpr int LONG_BASE = 10;
        char *error = nullptr;
        auto inet = std::strtol(address.c_str(), &error, LONG_BASE);
        if (error && *error == '\0' && inet >= 0 && inet <= UINT32_MAX) {
            in_addr addr{};
            addr.s_addr = static_cast<in_addr_t>(inet);
            address_ = inet_ntoa(addr);
        }
    } else if (family_ == Family::IPv6) {
        auto pos = address.find('%');
        if (pos == std::string::npos) {
            return;
        }
        auto subAddr = address.substr(0, pos);
        in6_addr ipv6{};
        if (inet_pton(AF_INET6, subAddr.c_str(), &ipv6) > 0) {
            address_ = subAddr;
            return;
        }
    }
}

void NetAddress::SetRawAddress(const std::string &address)
{
    address_ = address;
}

void NetAddress::SetAddress(const std::string &address)
{
    if (family_ == Family::IPv4) {
        struct in_addr ipv4;
        if (inet_pton(AF_INET, address.c_str(), &(ipv4.s_addr)) > 0) {
            address_ = address;
            return;
        }
    } else {
        struct in6_addr ipv6;
        if (inet_pton(AF_INET6, address.c_str(), &ipv6) > 0) {
            address_ = address;
            return;
        }
    }

    struct addrinfo hints;
    sa_family_t saFamily = GetSaFamily();
    if (memset_s(&hints, sizeof hints, 0, sizeof hints) != EOK) {
        NETSTACK_LOGE("memory operation fail");
    }
    hints.ai_family = saFamily;
    char ipStr[INET6_ADDRSTRLEN];
    struct addrinfo *res = nullptr;
    int status = getaddrinfo(address.c_str(), nullptr, &hints, &res);
    if (status != 0 || res == nullptr) {
        NETSTACK_LOGE("getaddrinfo status is %{public}d, error is %{public}s", status, gai_strerror(status));
        return;
    }

    void *addr = nullptr;
    if (res->ai_family == AF_INET) {
        auto *ipv4 = reinterpret_cast<struct sockaddr_in *>(res->ai_addr);
        addr = &(ipv4->sin_addr);
    } else {
        struct sockaddr_in6 *ipv6 = reinterpret_cast<struct sockaddr_in6 *>(res->ai_addr);
        addr = &(ipv6->sin6_addr);
    }
    inet_ntop(res->ai_family, addr, ipStr, sizeof ipStr);
    address_ = ipStr;
    freeaddrinfo(res);
}

void NetAddress::SetAddress(const std::string &address, bool resolveDns)
{
    if (!resolveDns && family_ == Family::DOMAIN_NAME) {
        address_ = address;
    } else {
        SetAddress(address);
    }
}

void NetAddress::SetFamilyByJsValue(uint32_t family)
{
    if (static_cast<Family>(family) == Family::IPv4) {
        family_ = Family::IPv4;
    } else if (static_cast<Family>(family) == Family::IPv6) {
        family_ = Family::IPv6;
    } else if (static_cast<Family>(family) == Family::DOMAIN_NAME) {
        family_ = Family::DOMAIN_NAME;
    } else {
        // do nothing
    }
}

void NetAddress::SetFamilyBySaFamily(sa_family_t family)
{
    if (family == AF_INET6) {
        family_ = Family::IPv6;
    }
}

void NetAddress::SetPort(uint16_t port)
{
    port_ = port;
}

const std::string &NetAddress::GetAddress() const
{
    return address_;
}

sa_family_t NetAddress::GetSaFamily() const
{
    if (family_ == Family::IPv6) {
        return AF_INET6;
    }
    return AF_INET;
}

uint32_t NetAddress::GetJsValueFamily() const
{
    return static_cast<uint32_t>(family_);
}

uint16_t NetAddress::GetPort() const
{
    return port_;
}

NetAddress::Family NetAddress::GetFamily() const
{
    return family_;
}

NetAddress &NetAddress::operator=(const NetAddress &other)
{
    address_ = other.GetAddress();
    family_ = other.GetFamily();
    port_ = other.GetPort();
    return *this;
}
} // namespace OHOS::NetStack::Socket
