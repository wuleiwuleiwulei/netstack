/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef SOCKET_EXEC_COMMON_H
#define SOCKET_EXEC_COMMON_H

#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "netstack_log.h"

namespace OHOS::NetStack::Socket {
class ExecCommonUtils {
public:
static bool MakeNonBlock(int sock)
{
    int flags = fcntl(sock, F_GETFL, 0);
    while (flags == -1 && errno == EINTR) {
        flags = fcntl(sock, F_GETFL, 0);
    }
    if (flags == -1) {
        NETSTACK_LOGE("make non block failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    int ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    while (ret == -1 && errno == EINTR) {
        ret = fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
    if (ret == -1) {
        NETSTACK_LOGE("make non block failed, socket is %{public}d, errno is %{public}d", sock, errno);
        return false;
    }
    return true;
}

static int MakeTcpSocket(sa_family_t family, bool needNonblock = true)
{
    if (family != AF_INET && family != AF_INET6) {
        return -1;
    }
    int sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    NETSTACK_LOGI("new tcp socket is %{public}d", sock);
    if (sock < 0) {
        NETSTACK_LOGE("make tcp socket failed, errno is %{public}d", errno);
        return -1;
    }
    if (needNonblock && !MakeNonBlock(sock)) {
        close(sock);
        return -1;
    }
    return sock;
}

static int MakeUdpSocket(sa_family_t family)
{
    if (family != AF_INET && family != AF_INET6) {
        return -1;
    }
    int sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    NETSTACK_LOGI("new udp socket is %{public}d", sock);
    if (sock < 0) {
        NETSTACK_LOGE("make udp socket failed, errno is %{public}d", errno);
        return -1;
    }
    if (!MakeNonBlock(sock)) {
        close(sock);
        return -1;
    }
    return sock;
}

static int MakeLocalSocket(int socketType, bool needNonblock = true)
{
    int sock = socket(AF_UNIX, socketType, 0);
    NETSTACK_LOGI("new local socket is %{public}d", sock);
    if (sock < 0) {
        NETSTACK_LOGE("make local socket failed, errno is %{public}d", errno);
        return -1;
    }
    if (needNonblock && !MakeNonBlock(sock)) {
        close(sock);
        return -1;
    }
    return sock;
}
};
}

std::string ConvertAddressToIp(const std::string &address, sa_family_t family);

bool IpMatchFamily(const std::string &address, sa_family_t family);

bool NonBlockConnect(int sock, sockaddr *addr, socklen_t addrLen, uint32_t timeoutMSec);

bool PollSendData(int sock, const char *data, size_t size, sockaddr *addr, socklen_t addrLen);

int ConfirmSocketTimeoutMs(int sock, int type, int defaultValue);

int ConfirmBufferSize(int sock);

#endif