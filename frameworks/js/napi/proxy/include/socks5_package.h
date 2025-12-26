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


#ifndef COMMUNICATION_NETSTACK_SOCKS5_PACKAGE_H
#define COMMUNICATION_NETSTACK_SOCKS5_PACKAGE_H


#include <sys/types.h>
#include <sys/socket.h>
#include <map>
#include <string>
#include <vector>

#include "net_address.h"
#include "socks5.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {

const uint8_t VERSION = 0x05;
const int IPV4_LEN = 4;
const int IPV6_LEN = 16;

class Socks5Request {
public:
    Socks5Request() = default;
    virtual ~Socks5Request() = default;
    virtual std::string Serialize() = 0;
};

class Socks5Response {
public:
    Socks5Response() = default;
    virtual ~Socks5Response() = default;
    virtual bool Deserialize(const void *data, size_t len) = 0;
};

class Socks5MethodRequest : public Socks5Request {
public:
    uint8_t version_;
    std::vector<Socks5MethodType> methods_;

    std::string Serialize();
};

class Socks5MethodResponse : public Socks5Response {
public:
    uint8_t version_;
    uint8_t method_;

    bool Deserialize(const void *data, size_t len);
};

class Socks5AuthRequest : public Socks5Request {
public:
    uint8_t version_;
    std::string username_;
    std::string password_;

    std::string Serialize();
};

class Socks5AuthResponse : public Socks5Response {
public:
    uint8_t version_;
    uint8_t status_;

    bool Deserialize(const void *data, size_t len);
};

class Socks5ProxyRequest : public Socks5Request {
public:
    uint8_t version_;
    Socks5Command cmd_;
    uint8_t reserved_;
    Socks5AddrType addrType_;
    std::string destAddr_;
    uint16_t destPort_;

    std::string Serialize();
};

class Socks5ProxyResponse : public Socks5Response {
public:
    uint8_t version_;
    uint8_t status_;
    uint8_t reserved_;
    Socks5AddrType addrType_;
    std::string destAddr_;
    uint16_t destPort_;

    bool Deserialize(const void *data, size_t len);
};

class Socks5UdpHeader : public Socks5Request {
public:
    uint16_t reserved_;
    uint8_t frag_;
    Socks5AddrType addrType_;
    std::string destAddr_;
    uint16_t dstPort_;

    std::string Serialize();
    bool Deserialize(const void *data, size_t len);
};

}  // Socks5
}  // NetStack
}  // OHOS
#endif  //COMMUNICATION_NETSTACK_SOCKS5_PACKAGE_H