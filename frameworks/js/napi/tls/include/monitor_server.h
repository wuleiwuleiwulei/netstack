/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef TLS_MONITOR_SERVER_H
#define TLS_MONITOR_SERVER_H

#include <cstdint>
#include <napi/native_api.h>
#include <queue>
#include <set>
#include <string>
#include <string_view>

#include "event_manager.h"
#include "singleton.h"
#include "socket_remote_info.h"
#include "tls.h"
#include "tls_socket_server.h"
namespace OHOS {
namespace NetStack {
namespace TlsSocketServer {
struct MessagerServerQueue {
    std::queue<int> clientFdQueue;
    std::queue<std::string> dataQueue;
    std::queue<Socket::SocketRemoteInfo> remoteInfoQueue;
};

class MonitorServer final {
    DECLARE_DELAYED_SINGLETON(MonitorServer);

public:
    napi_value On(napi_env env, napi_callback_info info);
    napi_value Off(napi_env env, napi_callback_info info);

    napi_value ConnectionOn(napi_env env, napi_callback_info info);
    napi_value ConnectionOff(napi_env env, napi_callback_info info);
    void TLSServerRegEvent(std::string event, TLSSocketServer *tlsSocketServer,
        const std::shared_ptr<EventManager> &eventManager);
    void TLSConnectionRegEvent(std::string event, TLSSocketServer *tlsSocketServer, int clientId,
                               const std::shared_ptr<EventManager> &eventManager);
    void TLSConnectionUnRegEvent(std::string event, TLSSocketServer *tlsSocketServer, int clientId);
    class MessageParma {
    public:
        int clientID;
        std::shared_ptr<EventManager> eventManager;
    };

    class MessageRecvParma {
    public:
        int clientID;
        std::string data;
        Socket::SocketRemoteInfo remoteInfo_;
    };

public:
    int clientFd_ = -1;
    std::string data_;
    Socket::SocketRemoteInfo remoteInfo_;
    MessagerServerQueue messagerServerQueue_;
    int32_t errorNumber_ = 0;
    std::string errorString_;

private:

    void InsertEventMessage(TLSSocketServer *tlsSocketServer, int clientId,
        const std::shared_ptr<EventManager> &eventManager);
};
} // namespace TlsSocketServer
} // namespace NetStack
} // namespace OHOS
#endif // TLS_MONITOR_SERVER_H
