/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef TLS_MONITOR_H
#define TLS_MONITOR_H

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
#include "tls_socket.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {

class Monitor final {
    DECLARE_DELAYED_SINGLETON(Monitor);

public:
    napi_value On(napi_env env, napi_callback_info info);
    napi_value Off(napi_env env, napi_callback_info info);
    class MessageRecvParma {
    public:
        std::string data_;
        Socket::SocketRemoteInfo remoteInfo_;
    };
    class ErrorRecvParma {
    public:
        int32_t errorNumber_ = 0;
        std::string errorString_;
    };

private:
    void ParserEventForOn(const std::string event, const std::shared_ptr<TLSSocket> &tlsSocket,
        const std::shared_ptr<EventManager> &manager);
    void ParserEventForOff(const std::string event, const std::shared_ptr<TLSSocket> &tlsSocket);
    void AddEventMessage(const std::shared_ptr<TLSSocket> &tlsSocket,
        const std::shared_ptr<EventManager> &manager) const;
};
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
#endif // TLS_CONTEXT_MONITOR_CONTEXT_H
