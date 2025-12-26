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

#ifndef COMMUNICATION_NETSTACK_SOCKS5_INSTANCE_H
#define COMMUNICATION_NETSTACK_SOCKS5_INSTANCE_H

#include <vector>
#include <memory>
#include <mutex>
#include <string>

#include "net_address.h"
#include "proxy_options.h"
#include "socks5.h"
#include "socks5_method.h"
#include "socket_exec.h"

namespace OHOS {
namespace NetStack {
namespace Socks5 {
class Socks5Instance {
public:
    Socks5Instance() = default;
    virtual ~Socks5Instance() = default;

    virtual bool Connect() = 0;
    virtual bool RemoveHeader(void *data, size_t &len, int af);
    virtual void AddHeader();
    virtual std::string GetHeader();
    virtual void SetHeader(std::string header);
    virtual void Close();

    void SetSocks5Option(const std::shared_ptr<Socks5Option> &opt);
    void SetDestAddress(const Socket::NetAddress &dest);
    bool IsConnected() const;
    void UpdateErrorInfo(Socks5Status status);
    void UpdateErrorInfo(int32_t errCode, const std::string &errMessage);
    int32_t GetErrorCode() const;
    std::string GetErrorMessage() const;
    void OnProxySocketError();
    void SetSocks5Instance(const std::shared_ptr<Socks5Instance> &socks5Inst);
    Socket::NetAddress GetProxyBindAddress() const;
    int GetSocketId() const;
    Socket::SocketExec::SocketRecvCallback GetProxySocketRecvCallback() const;
    bool ConnectProxy();
    void CloseSocket();

protected:
    bool RequestMethod(const std::vector<Socks5MethodType> &methods);
    std::shared_ptr<Socks5Method> CreateSocks5MethodByType(Socks5MethodType type) const;
    bool DoConnect(Socks5Command command);

    int32_t socketId_{SOCKS5_INVALID_SOCKET_FD};
    Socket::NetAddress dest_{};
    std::shared_ptr<Socks5Option> options_{nullptr};
    std::shared_ptr<Socks5Method> method_{nullptr};
    Socks5AuthState state_{Socks5AuthState::INIT};
    Socket::NetAddress proxyBindAddr_{};
    int32_t doConnectCount_{};

private:
    int32_t errorCode_{};
    std::string errorMessage_{};
    std::shared_ptr<Socks5Instance> socks5Instance_;
};

class Socks5TcpInstance final : public Socks5Instance {
public:
    Socks5TcpInstance() = delete;
    explicit Socks5TcpInstance(int32_t socketId);
    ~Socks5TcpInstance() = default;

    bool Connect();
};

class Socks5UdpInstance final : public Socks5Instance, std::enable_shared_from_this<Socks5UdpInstance> {
public:
    Socks5UdpInstance() = default;
    ~Socks5UdpInstance();

    bool Connect() override;
    bool RemoveHeader(void *data, size_t &len, int af) override;
    void AddHeader() override;
    std::string GetHeader() override;
    void SetHeader(std::string header) override;
    void Close() override;

private:
    bool CreateSocket();

    std::string header_;
};

class Socks5TlsInstance final : public Socks5Instance {
public:
    Socks5TlsInstance() = delete;
    explicit Socks5TlsInstance(int32_t socketId);
    ~Socks5TlsInstance() = default;

    bool Connect();
};
} // Socks5
} // NetStack
} // OHOS
#endif // COMMUNICATION_NETSTACK_SOCKS5_INSTANCE_H
