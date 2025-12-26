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

#include "socks5_package.h"

#include <netinet/in.h>

#include "netstack_log.h"
#include "socks5_instance.h"
#include "socks5_none_method.h"
#include "socks5_passwd_method.h"
#include "socks5_utils.h"
#include "securec.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {

/*
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+ */
std::string Socks5MethodRequest::Serialize()
{
    std::string serialized;
    serialized.resize(2 + methods_.size()); // 2 = VER + NMETHODS
    serialized[0] = version_;
    serialized[1] = static_cast<uint8_t>(methods_.size());

    size_t pos = 2;
    for (const auto& method : methods_) {
        serialized[pos++] = static_cast<uint8_t>(method);
    }

    return serialized;
}

/*
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+ */
bool Socks5MethodResponse::Deserialize(const void *data, size_t len)
{
    if (len < 2) {  // 2 = VER + METHOD
        return false;
    }

    const uint8_t *buffer = static_cast<const uint8_t*>(data);
    version_ = buffer[0];
    method_ = buffer[1];

    return true;
}

/*
+----+------+----------+------+----------+
|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+----+------+----------+------+----------+
| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
+----+------+----------+------+----------+ */
std::string Socks5AuthRequest::Serialize()
{
    std::string serialized;
    serialized.resize(3 + username_.length() + password_.length()); // 3 = VER + ULEN + PLEN
    serialized[0] = version_;
    serialized[1] = static_cast<uint8_t>(username_.length());

    size_t pos = 2;
    if (memcpy_s(&serialized[pos], serialized.size() - pos, username_.c_str(), username_.length()) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
        return "";
    }

    pos += username_.length();
    serialized[pos++] = static_cast<uint8_t>(password_.length());
    if (memcpy_s(&serialized[pos], serialized.size() - pos, password_.c_str(), password_.length()) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
        return "";
    }

    return serialized;
}

/*
+----+--------+
|VER | STATUS |
+----+--------+
| 1  |   1    |
+----+--------+ */
bool Socks5AuthResponse::Deserialize(const void *data, size_t len)
{
    if (len < 2) { // 2 = VER + STATUS
        return false;
    }

    const uint8_t *buffer = static_cast<const uint8_t*>(data);
    version_ = buffer[0];
    status_ = buffer[1];

    return true;
}

static int CopyAddrToStr(Socks5AddrType addrType, std::string &destAddr, std::string &serialized, size_t pos)
{
    switch (addrType) {
        case Socks5AddrType::IPV4: {
            struct in_addr ipv4Address;
            if (inet_pton(AF_INET, destAddr.c_str(), &ipv4Address) <= 0) {
                NETSTACK_LOGE("inet_pton failed!");
                return -1;
            }
            if (memcpy_s(&serialized[pos], serialized.size() - pos, &ipv4Address, sizeof(ipv4Address)) != EOK) {
                NETSTACK_LOGE("memcpy_s failed!");
                return -1;
            }
            return pos + sizeof(ipv4Address);
        }
        case Socks5AddrType::DOMAIN_NAME: {
            uint8_t domainLength = static_cast<uint8_t>(destAddr.length());
            serialized[pos] = domainLength;
            if (memcpy_s(&serialized[pos + 1], serialized.size() - pos - 1, destAddr.c_str(), domainLength) != EOK) {
                NETSTACK_LOGE("memcpy_s failed!");
                return -1;
            }
            return pos + 1 + domainLength;
        }
        case Socks5AddrType::IPV6: {
            struct in6_addr ipv6Address;
            if (inet_pton(AF_INET6, destAddr.c_str(), &ipv6Address) <= 0) {
                NETSTACK_LOGE("inet_pton failed!");
                return -1;
            }
            if (memcpy_s(&serialized[pos], serialized.size() - pos, &ipv6Address, sizeof(ipv6Address)) != EOK) {
                NETSTACK_LOGE("memcpy_s failed!");
                return -1;
            }
            return pos + sizeof(ipv6Address);
        }
    }
    return -1;
}

static void ResizeStrByAType(Socks5AddrType addrType, std::string &destAddr, size_t otherLen,
    std::string &serialized)
{
    switch (addrType) {
        case Socks5AddrType::IPV4:
            serialized.resize(otherLen + IPV4_LEN);
            break;
        case Socks5AddrType::DOMAIN_NAME:
            serialized.resize(otherLen + destAddr.length() + 1); // 1: size of DOMAIN_LEN
            break;
        case Socks5AddrType::IPV6:
            serialized.resize(otherLen + IPV6_LEN);
            break;
    }
}

/*
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+ */
std::string Socks5ProxyRequest::Serialize()
{
    int excludeStrLen = 6; // 6 = VER + CMD + RSV + ATYP + DST.PORT
    std::string serialized;

    ResizeStrByAType(addrType_, destAddr_, excludeStrLen, serialized);

    serialized[0] = version_;
    serialized[1] = static_cast<uint8_t>(cmd_);
    serialized[2] = reserved_; // 2: RSV
    serialized[3] = static_cast<uint8_t>(addrType_); // 3: ATYP

    int pos = CopyAddrToStr(addrType_, destAddr_, serialized, 4); // 4: DST.ADDR
    if (pos < 0) {
        return "";
    }

    uint16_t netPort = htons(destPort_);
    if (memcpy_s(&serialized[pos], serialized.size() - pos, &netPort, sizeof(netPort)) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
        return "";
    }

    return serialized;
}

static size_t GetAddrLen(Socks5AddrType addrType, const uint8_t *buffer, size_t domainLenIdx)
{
    switch (addrType) {
        case Socks5AddrType::IPV4:
            return IPV4_LEN;
        case Socks5AddrType::DOMAIN_NAME:
            return buffer[domainLenIdx] + 1;  // DOMAIN_LEN + DOMAIN
        case Socks5AddrType::IPV6:
            return IPV6_LEN;
    }
    return 0;
}

static void GetAddrStr(Socks5AddrType addrType, const uint8_t *buffer, size_t hdrLen,
    size_t domainIdx, std::string &destAddr)
{
    switch (addrType) {
        case Socks5AddrType::IPV4: {
            char ipv4Str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &buffer[hdrLen], ipv4Str, sizeof(ipv4Str));
            destAddr = ipv4Str;
            break;
        }
        case Socks5AddrType::DOMAIN_NAME: {
            uint8_t domainLength = buffer[hdrLen];
            destAddr.assign(reinterpret_cast<const char *>(&buffer[domainIdx]), domainLength);
            break;
        }
        case Socks5AddrType::IPV6: {
            char ipv6Str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &buffer[hdrLen], ipv6Str, sizeof(ipv6Str));
            destAddr = ipv6Str;
            break;
        }
    }
}

/*
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+ */
bool Socks5ProxyResponse::Deserialize(const void *data, size_t len)
{
    const int hdrLen = 4;  // 4 = VER + REP + RSV + ATYP
    if (len < hdrLen + 2) { // 2 = PORT
        return false;
    }

    const uint8_t *buffer = static_cast<const uint8_t*>(data);

    version_ = buffer[0];
    status_ = buffer[1];
    reserved_ = buffer[2]; // 2: index of RSV
    addrType_ = static_cast<Socks5AddrType>(buffer[3]); // 3: index of ATYP

    size_t addrLen = GetAddrLen(addrType_, buffer, 4); // 4: index of domain len
    if (addrLen == 0 || len < hdrLen + addrLen + 2) { // 2: PORT size
        return false;
    }

    GetAddrStr(addrType_, buffer, hdrLen, 5, destAddr_); // 5: index of DOMAIN
    destPort_ = (buffer[len - 2] << 8) | buffer[len - 1]; // 8: char bits, 2: port size
    return true;
}

/*
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+ */
std::string Socks5UdpHeader::Serialize()
{
    int excludeStrLen = 6; // 6 = RSV + FRAG + ATYP + DST.PORT
    std::string serialized;
    ResizeStrByAType(addrType_, destAddr_, excludeStrLen, serialized);

    if (memcpy_s(&serialized[0], serialized.size(), &reserved_, sizeof(reserved_)) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
        return "";
    }
    serialized[2] = frag_;  // 2: FRAG
    serialized[3] = static_cast<uint8_t>(addrType_); // 3: ATYP

    int pos = CopyAddrToStr(addrType_, destAddr_, serialized, 4); // 4: DST.ADDR
    if (pos < 0) {
        return "";
    }

    uint16_t netPort = htons(dstPort_);
    if (memcpy_s(&serialized[pos], serialized.size() - pos, &netPort, sizeof(netPort)) != EOK) {
        NETSTACK_LOGE("memcpy_s failed!");
        return "";
    }

    return serialized;
}

/*
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+ */
bool Socks5UdpHeader::Deserialize(const void *data, size_t len)
{
    const int hdrLen = 4;  // 4 = RSV + FRAG + ATYP
    const uint8_t *buffer = static_cast<const uint8_t*>(data);
    if ((len < hdrLen + 2) || (buffer[2] | buffer[1] | (buffer[0] != 0))) { // 2: index of FRAG
        return false;
    }

    addrType_ = static_cast<Socks5AddrType>(buffer[3]);  // 3: index of ATYP

    size_t addrLen = GetAddrLen(addrType_, buffer, 4); // 4: index of domain len
    if (addrLen == 0 || len < hdrLen + addrLen + 2) { // 2: port size
        return false;
    }

    GetAddrStr(addrType_, buffer, hdrLen, 5, destAddr_); // 5: index of DOMAIN
    dstPort_ = (buffer[len - 2] << 8) | buffer[len - 1]; // 8: char bits, 2: port size
    return true;
}

} // Socks5
} // NetStack
} // OHOS