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

#include "socks5_instance.h"

#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/tcp.h>

#include "netstack_log.h"
#include "socket_exec.h"
#include "socket_exec_common.h"
#include "socks5_none_method.h"
#include "socks5_passwd_method.h"
#include "socks5_package.h"
#include "socks5_utils.h"
#include "securec.h"

static constexpr const int INET_SOCKS5_UDP_HEADER_LEN = 10;

static constexpr const int INET6_SOCKS5_UDP_HEADER_LEN = 22;

static constexpr const int SOCKS5_DO_CONNECT_COUNT_MAX = 3;

namespace OHOS {
namespace NetStack {
namespace Socks5 {

void Socks5Instance::UpdateErrorInfo(Socks5Status status)
{
    errorCode_ = static_cast<int32_t>(status);
    auto iter = g_errStatusMap.find(status);
    if (iter != g_errStatusMap.end()) {
        errorMessage_ = iter->second;
    } else {
        errorMessage_.clear();
    }
}

void Socks5Instance::UpdateErrorInfo(int32_t errCode, const std::string &errMessage)
{
    errorCode_ = errCode;
    errorMessage_ = errMessage;
}

void Socks5Instance::SetSocks5Option(const std::shared_ptr<Socks5Option> &opt)
{
    options_ = opt;
}

void Socks5Instance::SetDestAddress(const Socket::NetAddress &dest)
{
    this->dest_ = dest;
}

bool Socks5Instance::IsConnected() const
{
    return state_ == Socks5AuthState::SUCCESS;
}

bool Socks5Instance::DoConnect(Socks5Command command)
{
    if (doConnectCount_++ > SOCKS5_DO_CONNECT_COUNT_MAX) {
        NETSTACK_LOGE("socks5 instance connect count over %{public}d times socket:%{public}d",
                      SOCKS5_DO_CONNECT_COUNT_MAX, socketId_);
        return false;
    }

    if (!RequestMethod(SOCKS5_METHODS)) {
        NETSTACK_LOGE("socks5 instance fail to request method socket:%{public}d", socketId_);
        return false;
    }
    if (method_ == nullptr) {
        NETSTACK_LOGE("socks5 instance method is null socket:%{public}d", socketId_);
        UpdateErrorInfo(Socks5Status::SOCKS5_METHOD_NEGO_ERROR);
        return false;
    }
    if (!method_->RequestAuth(socketId_, options_->username_, options_->password_, options_->proxyAddress_)) {
        NETSTACK_LOGE("socks5 instance fail to auth socket:%{public}d", socketId_);
        return false;
    }
    const std::pair<bool, Socks5ProxyResponse> result{method_->RequestProxy(socketId_, command, dest_,
        options_->proxyAddress_)};
    if (!result.first) {
        NETSTACK_LOGE("socks5 instance fail to request proxy socket:%{public}d", socketId_);
        return false;
    }
    proxyBindAddr_.SetAddress(result.second.destAddr_, false);
    proxyBindAddr_.SetPort(result.second.destPort_);
    if (result.second.addrType_ == Socks5AddrType::IPV4) {
        proxyBindAddr_.SetFamilyByJsValue(static_cast<uint32_t>(Socket::NetAddress::Family::IPv4));
    } else if (result.second.addrType_ == Socks5AddrType::IPV6) {
        proxyBindAddr_.SetFamilyByJsValue(static_cast<uint32_t>(Socket::NetAddress::Family::IPv6));
    } else if (result.second.addrType_ == Socks5AddrType::DOMAIN_NAME) {
        proxyBindAddr_.SetFamilyByJsValue(static_cast<uint32_t>(Socket::NetAddress::Family::DOMAIN_NAME));
    } else {
        NETSTACK_LOGE("socks5 instance get unknow addrType:%{public}d socket:%{public}d",
            static_cast<uint32_t>(result.second.addrType_), socketId_);
    }
    state_ = Socks5AuthState::SUCCESS;
    return true;
}

int32_t Socks5Instance::GetErrorCode() const
{
    return errorCode_;
}

std::string Socks5Instance::GetErrorMessage() const
{
    return errorMessage_;
}

void Socks5Instance::OnProxySocketError()
{
    NETSTACK_LOGE("socks5 instance tcp error socket:%{public}d", socketId_);
    state_ = Socks5AuthState::FAIL;
}

void Socks5Instance::SetSocks5Instance(const std::shared_ptr<Socks5Instance> &socks5Inst)
{
    socks5Instance_ = socks5Inst;
}

Socket::NetAddress Socks5Instance::GetProxyBindAddress() const
{
    return proxyBindAddr_;
}

int Socks5Instance::GetSocketId() const
{
    return socketId_;
}

bool Socks5Instance::ConnectProxy()
{
    const socklen_t addrLen{Socks5Utils::GetAddressLen(options_->proxyAddress_.netAddress_)};
    // use default value
    const uint32_t timeoutMSec{0U};
    if (!NonBlockConnect(socketId_, options_->proxyAddress_.addr_, addrLen, timeoutMSec)) {
        NETSTACK_LOGE("socks5 instance fail to connect proxy");
        UpdateErrorInfo(Socks5Status::SOCKS5_FAIL_TO_CONNECT_PROXY);
        return false;
    }
    return true;
}

void Socks5Instance::CloseSocket()
{
    if (socketId_ != SOCKS5_INVALID_SOCKET_FD) {
        NETSTACK_LOGI("socks5 instance close socket:%{public}d", socketId_);
        static_cast<void>(::close(socketId_));
        socketId_ = SOCKS5_INVALID_SOCKET_FD;
    }
}

static bool SocketRecvHandle(int socketId, std::pair<std::unique_ptr<char[]> &, int> &bufInfo,
    std::pair<sockaddr *, socklen_t> &addrInfo, const Socket::SocketExec::MessageCallback &callback)
{
    const auto recvLen = recv(socketId, bufInfo.first.get(), bufInfo.second, 0);
    if (recvLen > 0) {
        return true;
    }
    const int32_t errCode{errno};
    if ((errCode == EAGAIN) || (errCode == EINTR)) {
        return true;
    }
    Socks5::Socks5Utils::PrintRecvErrMsg(socketId, errCode, recvLen, "SocketRecvHandle");

    auto manager = callback.GetEventManager();
    if (manager != nullptr) {
        manager->GetProxyData()->OnProxySocketError();
    } else {
        NETSTACK_LOGE("manager is error");
    }
    return false;
}

Socket::SocketExec::SocketRecvCallback Socks5Instance::GetProxySocketRecvCallback() const
{
    return SocketRecvHandle;
}

bool Socks5Instance::RequestMethod(const std::vector<Socks5MethodType> &methods)
{
    Socks5MethodRequest request{};
    request.version_ = SOCKS5_VERSION;
    request.methods_ = methods;

    const socklen_t addrLen{Socks5Utils::GetAddressLen(options_->proxyAddress_.netAddress_)};
    const std::pair<sockaddr *, socklen_t> addrInfo{options_->proxyAddress_.addr_, addrLen};
    Socks5MethodResponse response{};
    if (!Socks5Utils::RequestProxyServer(socks5Instance_, socketId_, addrInfo, &request, &response)) {
        NETSTACK_LOGE("RequestMethod failed, socket: %{public}d", socketId_);
        return false;
    }
    Socks5MethodType methodType{static_cast<Socks5MethodType>(response.method_)};
    method_ = CreateSocks5MethodByType(methodType);
    return true;
}

std::shared_ptr<Socks5Method> Socks5Instance::CreateSocks5MethodByType(Socks5MethodType type) const
{
    if (type == Socks5MethodType::NO_AUTH) {
        return std::make_shared<Socks5NoneMethod>(socks5Instance_);
    } else if (type == Socks5MethodType::PASSWORD) {
        return std::make_shared<Socks5PasswdMethod>(socks5Instance_);
    } else if (type == Socks5MethodType::GSSAPI) {
        NETSTACK_LOGE("socks5 instance not support GSSAPI now");
        return nullptr;
    } else {
        NETSTACK_LOGE("socks5 instance no method type:%{public}d", static_cast<int32_t>(type));
        return nullptr;
    }
}

Socks5TcpInstance::Socks5TcpInstance(int32_t socketId)
{
    socketId_ = socketId;
}

bool Socks5TcpInstance::Connect()
{
    NETSTACK_LOGD("socks5 tcp instance auth socket:%{public}d", socketId_);
    UpdateErrorInfo(0, "");
    if (state_ == Socks5AuthState::SUCCESS) {
        NETSTACK_LOGD("socks5 tcp instance auth already socket:%{public}d", socketId_);
        return true;
    }
    if (!ConnectProxy()) {
        CloseSocket();
        return false;
    }
    if (!DoConnect(Socks5Command::TCP_CONNECTION)) {
        CloseSocket();
        return false;
    }
    NETSTACK_LOGI("socks5 tcp instance auth successfully socket:%{public}d", socketId_);
    return true;
}

bool Socks5Instance::RemoveHeader(void *data, size_t &len, int af)
{
    return false;
}

void Socks5Instance::AddHeader()
{
}

std::string Socks5Instance::GetHeader()
{
    return std::string();
}

void Socks5Instance::SetHeader(std::string header)
{
}

void Socks5Instance::Close()
{
}

Socks5UdpInstance::~Socks5UdpInstance()
{
    CloseSocket();
}

bool Socks5UdpInstance::Connect()
{
    NETSTACK_LOGD("socks5 udp instance auth");
    UpdateErrorInfo(0, "");

    if (state_ == Socks5AuthState::SUCCESS) {
        NETSTACK_LOGD("socks5 udp instance auth already");
        return true;
    }
    if (!CreateSocket()) {
        return false;
    }
    if (!ConnectProxy()) {
        CloseSocket();
        return false;
    }
    if (!DoConnect(Socks5Command::UDP_ASSOCIATE)) {
        CloseSocket();
        return false;
    }
    NETSTACK_LOGI("socks5 udp instance auth successfully socket:%{public}d", socketId_);
    return true;
}

bool Socks5UdpInstance::CreateSocket()
{
    socketId_ = Socket::ExecCommonUtils::MakeTcpSocket(options_->proxyAddress_.netAddress_.GetSaFamily());
    if (socketId_ == SOCKS5_INVALID_SOCKET_FD) {
        NETSTACK_LOGE("socks5 udp instance fail to make tcp socket");
        UpdateErrorInfo(Socks5Status::SOCKS5_MAKE_SOCKET_ERROR);
        return false;
    }

    int keepalive = 1;
    if (setsockopt(socketId_, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
        NETSTACK_LOGE("socks5 udp instance fail to set keepalive");
        return false;
    }

    return true;
}

bool Socks5UdpInstance::RemoveHeader(void *data, size_t &len, int af)
{
    size_t headerLen = af == AF_INET ? INET_SOCKS5_UDP_HEADER_LEN : INET6_SOCKS5_UDP_HEADER_LEN;
    Socks5UdpHeader header{};

    if (data == nullptr || !header.Deserialize(data, len)) {
        NETSTACK_LOGE("not a valid socks5 udp header");
        return false;
    }

    if (len < headerLen) {
        NETSTACK_LOGE("fail to remove udp header");
        return false;
    }

    len -= headerLen;

    if (memmove_s(data, len, static_cast<uint8_t *>(data) + headerLen, len) != EOK) {
        NETSTACK_LOGE("memory copy failed");
        return false;
    }

    return true;
}

void Socks5UdpInstance::AddHeader()
{
    const Socket::NetAddress::Family family{dest_.GetFamily()};
    Socks5::Socks5AddrType addrType;

    if (family == Socket::NetAddress::Family::IPv4) {
        addrType = Socks5::Socks5AddrType::IPV4;
    } else if (family == Socket::NetAddress::Family::IPv6) {
        addrType = Socks5::Socks5AddrType::IPV6;
    } else if (family == Socket::NetAddress::Family::DOMAIN_NAME) {
        addrType = Socks5::Socks5AddrType::DOMAIN_NAME;
    } else {
        NETSTACK_LOGE("socks5 udp protocol address type error");
        return ;
    }

    Socks5::Socks5UdpHeader header{};
    header.addrType_ = addrType;
    header.destAddr_ = dest_.GetAddress();
    header.dstPort_ = dest_.GetPort();

    SetHeader(header.Serialize());
}

void Socks5UdpInstance::SetHeader(std::string header)
{
    header_ = header;
}

void Socks5UdpInstance::Close()
{
    CloseSocket();
}

std::string Socks5UdpInstance::GetHeader()
{
    return header_;
}

Socks5TlsInstance::Socks5TlsInstance(int32_t socketId)
{
    socketId_ = socketId;
}

bool Socks5TlsInstance::Connect()
{
    NETSTACK_LOGD("socks5 tls instance auth socket:%{public}d", socketId_);
    UpdateErrorInfo(0, "");
    if (state_ == Socks5AuthState::SUCCESS) {
        NETSTACK_LOGD("socks5 tls instance auth already socket:%{public}d", socketId_);
        return true;
    }
    Socket::ExecCommonUtils::MakeNonBlock(socketId_);
    if (!ConnectProxy()) {
        CloseSocket();
        return false;
    }
    if (!DoConnect(Socks5Command::TCP_CONNECTION)) {
        CloseSocket();
        return false;
    }
    NETSTACK_LOGI("socks5 tls instance auth successfully socket:%{public}d", socketId_);
    return true;
}
} // Socks5
} // NetStack
} // OHOS
