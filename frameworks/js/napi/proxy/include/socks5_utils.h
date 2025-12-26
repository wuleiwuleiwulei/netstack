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

#ifndef COMMUNICATION_NETSTACK_SOCKS5_UTILS_H
#define COMMUNICATION_NETSTACK_SOCKS5_UTILS_H

#include <thread>
#include <memory>
#include <string>
#include <sys/socket.h>

#include "net_address.h"
#include "socks5.h"
#include "socks5_instance.h"
#include "socks5_package.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {
class Socks5Utils {
public:
    static socklen_t GetAddressLen(const Socket::NetAddress &netAddress);
    static bool Send(int32_t socketId, const char *data, size_t size, sockaddr *addr, socklen_t addrLen);
    static std::pair<bool, Socks5Buffer> Recv(int32_t socketId, sockaddr *addr, socklen_t addrLen);
    static bool RequestProxyServer(std::shared_ptr<Socks5Instance> &socks5Inst, std::int32_t socketId,
        const std::pair<sockaddr *, socklen_t> &addrInfo, Socks5Request *req, Socks5Response *rsp);
    static std::string GetStatusMessage(Socks5Status status);
    static void PrintRecvErrMsg(int32_t socketId, const int32_t errCode, const int32_t recvLen,
        const std::string &tag);
    static void SetProxyAuthError(BaseContext *context, std::shared_ptr<Socks5::Socks5Instance> &socks5Inst);
};
}  // Socks5
}  // NetStack
}  // OHOS
#endif  // COMMUNICATION_NETSTACK_SOCKS5_UTILS_H