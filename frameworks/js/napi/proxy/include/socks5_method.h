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

#ifndef COMMUNICATION_NETSTACK_SOCKS5_METHOD_H
#define COMMUNICATION_NETSTACK_SOCKS5_METHOD_H

#include <memory>
#include <string>
#include <sys/types.h>

#include "net_address.h"
#include "socks5.h"
#include "socks5_package.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {
class Socks5Instance;
class Socks5Method {
public:
    Socks5Method(std::shared_ptr<Socks5Instance> socks5Inst) : socks5Inst_(socks5Inst){};
    virtual ~Socks5Method() = default;

    virtual bool RequestAuth(std::int32_t socketId, const std::string &userName, const std::string &password,
        const Socks5ProxyAddress &proxy) = 0;
    virtual std::pair<bool, Socks5ProxyResponse> RequestProxy(std::int32_t socketId, Socks5Command command,
        const Socket::NetAddress &destAddr, const Socks5ProxyAddress &proxy) = 0;

    std::shared_ptr<Socks5Instance> &GetSocks5Instance()
    {
        return socks5Inst_;
    }

private:
    std::shared_ptr<Socks5Instance> socks5Inst_{nullptr};
};
} // Socks5
} // NetStack
} // OHOS
#endif // COMMUNICATION_NETSTACK_SOCKS5_METHOD_H
