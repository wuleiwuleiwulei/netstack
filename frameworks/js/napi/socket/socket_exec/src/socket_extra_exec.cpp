/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "socket_exec.h"

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <fcntl.h>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

#include "context_key.h"
#include "event_list.h"
#include "napi_utils.h"
#include "netstack_common_utils.h"
#include "netstack_log.h"
#include "securec.h"
#include "socket_async_work.h"
#include "socket_module.h"

namespace OHOS::NetStack::Socket::SocketExec {
bool ExecGetLocalAddress(GetLocalAddressContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    auto socketFD = context->GetSocketFd();
    struct sockaddr_storage addr{};
    socklen_t addrLen = sizeof(addr);
    if (getsockname(socketFD, (struct sockaddr *)&addr, &addrLen) < 0) {
        context->SetNeedThrowException(true);
        context->SetErrorCode(errno);
        return false;
    }

    char ipStr[INET6_ADDRSTRLEN] = {0};
    Socket::NetAddress localAddress;
    if (addr.ss_family == AF_INET) {
        auto *addrIn = reinterpret_cast<struct sockaddr_in *>(&addr);
        inet_ntop(AF_INET, &addrIn->sin_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addrIn->sin_port));
        context->localAddress_ = localAddress;
    } else if (addr.ss_family == AF_INET6) {
        auto *addrIn6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);
        inet_ntop(AF_INET6, &addrIn6->sin6_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET6);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addrIn6->sin6_port));
        context->localAddress_ = localAddress;
    }
    return true;
}

bool ExecTcpServerGetLocalAddress(TcpServerGetLocalAddressContext *context)
{
    if (context == nullptr) {
        NETSTACK_LOGE("context is nullptr");
        return false;
    }
    auto socketFD = context->GetSocketFd();
    struct sockaddr_storage addr{};
    socklen_t addrLen = sizeof(addr);
    if (getsockname(socketFD, (struct sockaddr *)&addr, &addrLen) < 0) {
        context->SetNeedThrowException(true);
        context->SetErrorCode(errno);
        return false;
    }

    char ipStr[INET6_ADDRSTRLEN] = {0};
    Socket::NetAddress localAddress;
    if (addr.ss_family == AF_INET) {
        auto *addrIn = reinterpret_cast<struct sockaddr_in *>(&addr);
        inet_ntop(AF_INET, &addrIn->sin_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addrIn->sin_port));
        context->localAddress_ = localAddress;
    } else if (addr.ss_family == AF_INET6) {
        auto *addrIn6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);
        inet_ntop(AF_INET6, &addrIn6->sin6_addr, ipStr, sizeof(ipStr));
        localAddress.SetFamilyBySaFamily(AF_INET6);
        localAddress.SetRawAddress(ipStr);
        localAddress.SetPort(ntohs(addrIn6->sin6_port));
        context->localAddress_ = localAddress;
    }
    return true;
}

napi_value GetLocalAddressCallback(GetLocalAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    auto env = context->GetEnv();
    NapiUtils::SetStringPropertyUtf8(env, obj, KEY_ADDRESS, context->localAddress_.GetAddress());
    NapiUtils::SetUint32Property(env, obj, KEY_FAMILY, context->localAddress_.GetJsValueFamily());
    NapiUtils::SetUint32Property(env, obj, KEY_PORT, context->localAddress_.GetPort());
    return obj;
}

napi_value TcpConnectionGetLocalAddressCallback(TcpConnectionGetLocalAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    auto env = context->GetEnv();
    NapiUtils::SetStringPropertyUtf8(env, obj, KEY_ADDRESS, context->localAddress_.GetAddress());
    NapiUtils::SetUint32Property(env, obj, KEY_FAMILY, context->localAddress_.GetJsValueFamily());
    NapiUtils::SetUint32Property(env, obj, KEY_PORT, context->localAddress_.GetPort());
    return obj;
}

napi_value TcpConnectionGetSocketFdCallback(TcpServerGetSocketFdContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    int socketFd = context->socketFd_;
    return NapiUtils::CreateInt32(context->GetEnv(), socketFd);
}

napi_value TcpServerGetLocalAddressCallback(TcpServerGetLocalAddressContext *context)
{
    napi_value obj = NapiUtils::CreateObject(context->GetEnv());
    if (NapiUtils::GetValueType(context->GetEnv(), obj) != napi_object) {
        return NapiUtils::GetUndefined(context->GetEnv());
    }
    auto env = context->GetEnv();
    NapiUtils::SetStringPropertyUtf8(env, obj, KEY_ADDRESS, context->localAddress_.GetAddress());
    NapiUtils::SetUint32Property(env, obj, KEY_FAMILY, context->localAddress_.GetJsValueFamily());
    NapiUtils::SetUint32Property(env, obj, KEY_PORT, context->localAddress_.GetPort());
    return obj;
}
} // namespace OHOS::NetStack::Socket::SocketExec
