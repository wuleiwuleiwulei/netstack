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

#include "net_websocket_base_context.h"

namespace OHOS::NetStack::NetWebSocket {
WebSocketBaseContext::WebSocketBaseContext(CJWebsocketProxy *websocketProxy)
    : websocketProxy_(websocketProxy),
      errorCode_(0),
      parseOK_(false),
      requestOK_(false),
      permissionDenied_(false)
{
}

WebSocketBaseContext::~WebSocketBaseContext() = default;

CJWebsocketProxy* WebSocketBaseContext::GetWebsocketProxy()
{
    return websocketProxy_;
}

void WebSocketBaseContext::SetWebsocketProxy(CJWebsocketProxy *websocketProxy)
{
    websocketProxy_ = websocketProxy;
}

void WebSocketBaseContext::SetParseOK(bool parseOK)
{
    parseOK_ = parseOK;
}

bool WebSocketBaseContext::IsParseOK() const
{
    return parseOK_;
}

void WebSocketBaseContext::SetExecOK(bool requestOK)
{
    requestOK_ = requestOK;
}

bool WebSocketBaseContext::IsExecOK() const
{
    return requestOK_;
}

int32_t WebSocketBaseContext::GetErrorCode() const
{
    return errorCode_;
}

void WebSocketBaseContext::SetErrorCode(int32_t errorCode)
{
    errorCode_ = errorCode;
}

std::string WebSocketBaseContext::GetErrorMessage() const
{
    return errorMessage_;
}

void WebSocketBaseContext::SetError(int32_t errorCode, const std::string &errorMessage)
{
    errorCode_ = errorCode;
    errorMessage_ = errorMessage;
}

void WebSocketBaseContext::SetPermissionDenied(bool deny)
{
    permissionDenied_ = deny;
}

bool WebSocketBaseContext::IsPermissionDenied() const
{
    return permissionDenied_;
}
}