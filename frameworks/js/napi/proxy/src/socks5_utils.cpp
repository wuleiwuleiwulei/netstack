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

#include "socks5_utils.h"

#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>

#include "securec.h"
#include "netstack_log.h"
#include "socket_exec.h"
#include "socket_exec_common.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {
socklen_t Socks5Utils::GetAddressLen(const Socket::NetAddress &netAddress)
{
    const bool isIpv4{Socket::NetAddress::Family::IPv4 == netAddress.GetFamily()};
    const socklen_t addrLen{isIpv4 ? sizeof(sockaddr_in) : sizeof(sockaddr_in6)};
    return addrLen;
}

bool Socks5Utils::Send(int32_t socketId, const char *data, size_t size, sockaddr *addr, socklen_t addrLen)
{
    return PollSendData(socketId, data, size, addr, addrLen);
}

std::pair<bool, Socks5Buffer> Socks5Utils::Recv(int32_t socketId, sockaddr *addr, socklen_t addrLen)
{
    const int32_t bufferSize = ConfirmBufferSize(socketId);
    auto buf = std::make_unique<char[]>(bufferSize);
    constexpr int32_t pollTimeout{500};
    const int32_t timeoutMs = ConfirmSocketTimeoutMs(socketId, SO_RCVTIMEO, pollTimeout);
    while (true) {
        pollfd fds[1] = {{socketId, POLLIN, 0}};
        const int ret = poll(fds, 1, timeoutMs);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            NETSTACK_LOGE("socks5 poll to recv failed, socket is %{public}d, errno is %{public}d", socketId, errno);
            break;
        } else if (ret == 0) {
            continue;
        }
        socklen_t tempAddrLen{addrLen};
        const int32_t recvLen = recvfrom(socketId, buf.get(), bufferSize, 0, addr, &tempAddrLen);
        if (recvLen > 0) {
            Socks5Buffer msg{};
            msg.assign(buf.get(), recvLen);
            return {true, msg};
        }
        const int32_t errCode{errno};
        if ((errCode == EAGAIN) || (errCode == EINTR)) {
            continue;
        }
        PrintRecvErrMsg(socketId, errCode, recvLen, "Recv");
        break;
    }
    return {false, ""};
}

void Socks5Utils::PrintRecvErrMsg(int32_t socketId, const int32_t errCode, const int32_t recvLen,
    const std::string &tag)
{
    if ((errCode == 0) && (recvLen == 0)) {
        NETSTACK_LOGI("[%{public}s] socks5 closed by peer, socket:%{public}d, recvLen:%{public}d", tag.c_str(),
            socketId, recvLen);
    } else {
        NETSTACK_LOGE("[%{public}s] socks5 recv fail, socket:%{public}d, recvLen:%{public}d, errno:%{public}d",
                      tag.c_str(), socketId, recvLen, errCode);
    }
}

bool Socks5Utils::RequestProxyServer(std::shared_ptr<Socks5Instance> &socks5Inst, std::int32_t socketId,
    const std::pair<sockaddr *, socklen_t> &addrInfo, Socks5Request *req, Socks5Response *rsp)
{
    if ((req == nullptr) || (rsp == nullptr)) {
        NETSTACK_LOGE("socks5 req or rsp is null, socket is %{public}d", socketId);
        return false;
    }
    const Socks5Buffer msg{req->Serialize()};
    const size_t msgSize{msg.size()};
    if (msgSize == 0U) {
        socks5Inst->UpdateErrorInfo(Socks5Status::SOCKS5_SERIALIZE_ERROR);
        NETSTACK_LOGE("socks5 fail to serialize, socket is %{public}d", socketId);
        return false;
    }
    sockaddr *addr{addrInfo.first};
    const socklen_t addrLen{addrInfo.second};
    if (!Socks5Utils::Send(socketId, msg.data(), msgSize, addr, addrLen)) {
        socks5Inst->UpdateErrorInfo(Socks5Status::SOCKS5_FAIL_TO_SEND_MSG);
        NETSTACK_LOGE("socks5 fail to send message, socket is %{public}d", socketId);
        return false;
    }

    std::pair<bool, Socks5Buffer> result = Socks5Utils::Recv(socketId, addr, addrLen);
    if (!result.first) {
        socks5Inst->UpdateErrorInfo(Socks5Status::SOCKS5_FAIL_TO_RECV_MSG);
        NETSTACK_LOGE("socks5 fail to recv message, socket is %{public}d", socketId);
        return false;
    }

    if (!rsp->Deserialize(result.second.data(), result.second.size())) {
        socks5Inst->UpdateErrorInfo(Socks5Status::SOCKS5_DESERIALIZE_ERROR);
        NETSTACK_LOGE("socks5 fail to deserialize, socket is %{public}d", socketId);
        return false;
    }
    return true;
}

std::string Socks5Utils::GetStatusMessage(Socks5Status status)
{
    auto iter = g_errStatusMap.find(status);
    if (iter != g_errStatusMap.end()) {
        return iter->second;
    }
    return "Unknown status.";
}

void Socks5Utils::SetProxyAuthError(BaseContext *context, std::shared_ptr<Socks5::Socks5Instance> &socks5Inst)
{
    const int32_t errCode = socks5Inst->GetErrorCode();
    const std::string errMsg = socks5Inst->GetErrorMessage();
    NETSTACK_LOGE("socks5 auth failed, errCode:%{public}d, errMsg::%{public}s", errCode, errMsg.c_str());
    context->SetError(errCode, errMsg);
}
}  // Socks5
}  // NetStack
}  // OHOS
