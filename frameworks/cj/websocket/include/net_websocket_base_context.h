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

#ifndef NET_WEBSOCKET_BASE_CONTEXT_H
#define NET_WEBSOCKET_BASE_CONTEXT_H

#include <string>

#include "ffi_structs.h"

namespace OHOS::NetStack::NetWebSocket {
class CJWebsocketProxy;

class WebSocketBaseContext {
public:
    WebSocketBaseContext() = delete;

    WebSocketBaseContext(CJWebsocketProxy* websocketProxy);

    virtual ~WebSocketBaseContext();

    CJWebsocketProxy* GetWebsocketProxy();

    void SetWebsocketProxy(CJWebsocketProxy* websocketProxy);

    void SetParseOK(bool parseOK);
        
    [[nodiscard]] bool IsParseOK() const;

    void SetExecOK(bool requestOK);

    [[nodiscard]] bool IsExecOK() const;

    [[nodiscard]] virtual int32_t GetErrorCode() const;

    void SetErrorCode(int32_t errorCode);

    [[nodiscard]] virtual std::string GetErrorMessage() const;

    void SetError(int32_t errorCode, const std::string &errorMessage);

    void SetPermissionDenied(bool deny);

    bool IsPermissionDenied() const;

protected:
    CJWebsocketProxy* websocketProxy_;

private:
    int32_t errorCode_;

    bool parseOK_ = false;

    bool requestOK_ = false;

    bool permissionDenied_ = false;

    std::string errorMessage_;
};
}
#endif