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

#include "net_websocket_impl.h"

#include "netstack_log.h"
#include "net_websocket_exec.h"

namespace OHOS::NetStack::NetWebSocket {
WebSocketConnectContext* CJWebsocketImpl::Connect(std::string url, CWebSocketRequestOptions *opt,
                                                  CJWebsocketProxy *websocketProxy)
{
    auto context = new (std::nothrow) WebSocketConnectContext(nullptr);
    if (context == nullptr) {
        return nullptr;
    }
    context->SetWebsocketProxy(websocketProxy);
    context->ParseParams(url, opt);
    if (!context->IsParseOK()) {
        // context.setxxx
        return context;
    }
    NetWebSocketExec::ExecConnect(context);
    return context;
}

WebSocketSendContext *CJWebsocketImpl::Send(CArrUI8 data, CJWebsocketProxy *websocketProxy, bool stringType)
{
    auto context = new (std::nothrow) WebSocketSendContext(nullptr);
    if (context == nullptr) {
        return nullptr;
    }
    context->SetWebsocketProxy(websocketProxy);
    context->ParseParams(data, stringType);
    if (!context->IsParseOK()) {
        // context.setxxx
        return context;
    }
    NetWebSocketExec::ExecSend(context);
    return context;
}

WebSocketCloseContext *CJWebsocketImpl::Close(CWebSocketCloseOptions *opt, CJWebsocketProxy *websocketProxy)
{
    auto context = new (std::nothrow) WebSocketCloseContext(nullptr);
    if (context == nullptr) {
        return nullptr;
    }
    context->SetWebsocketProxy(websocketProxy);
    context->ParseParams(opt);
    if (!context->IsParseOK()) {
        // context.setxxx
        return context;
    }
    NetWebSocketExec::ExecClose(context);
    return context;
}

bool CJWebsocketImpl::OnWithProxy(int32_t typeId, void (*callback)(CWebSocketCallbackData *data),
    CJWebsocketProxy *websocketProxy)
{
    websocketProxy->AddCallback2Map(typeId, CJLambda::Create(callback));
    return true;
}

bool CJWebsocketImpl::OffWithProxy(int32_t typeId, CJWebsocketProxy *websocketProxy)
{
    websocketProxy->DelCallback(typeId);
    return true;
}

std::shared_ptr<NetWebSocket::WebSocketContext> CJWebsocketProxy::GetWebSocketContext()
{
    std::lock_guard<std::mutex> lock(contextMutex_);
    return webSocketContext_;
}

void CJWebsocketProxy::SetWebSocketContext(const std::shared_ptr<NetWebSocket::WebSocketContext> &websocketContext)
{
    std::lock_guard<std::mutex> lock(contextMutex_);
    webSocketContext_ = websocketContext;
}

void CJWebsocketProxy::EmitCallBack(CWebSocketCallbackData *data)
{
    auto callback = FindCallback(data->typeId);
    if (callback == std::nullopt) {
        NETSTACK_LOGI("EmitCallBack failed, %{public}d not find.", data->typeId);
        return;
    }
    callback.value()(data);
}

const std::string &CJWebsocketProxy::GetWebSocketTextData()
{
    return webSocketTextData_;
}

void CJWebsocketProxy::AppendWebSocketTextData(void *data, size_t length)
{
    webSocketTextData_.append(reinterpret_cast<char *>(data), length);
}

const std::string &CJWebsocketProxy::GetWebSocketBinaryData()
{
    return webSocketBinaryData_;
}

void CJWebsocketProxy::AppendWebSocketBinaryData(void *data, size_t length)
{
    webSocketBinaryData_.append(reinterpret_cast<char *>(data), length);
}

void CJWebsocketProxy::SetQueueData(void *data)
{
    std::lock_guard<std::mutex> lock(dataQueueMutex_);
    dataQueue_.push(data);
}

void *CJWebsocketProxy::GetQueueData()
{
    std::lock_guard<std::mutex> lock(dataQueueMutex_);
    if (!dataQueue_.empty()) {
        auto data = dataQueue_.front();
        dataQueue_.pop();
        return data;
    }
    NETSTACK_LOGE("CJWebsocketProxy data queue is empty");
    return nullptr;
}

void CJWebsocketProxy::ClearWebSocketTextData()
{
    webSocketTextData_.clear();
}

void CJWebsocketProxy::ClearWebSocketBinaryData()
{
    webSocketBinaryData_.clear();
}

void CJWebsocketProxy::AddCallback2Map(int32_t typeId, WebSocketCallback callback)
{
    std::lock_guard<std::mutex> mutex(mutex_);
    eventMap_[typeId] = callback;
}

void CJWebsocketProxy::DelCallback(int32_t typeId)
{
    std::lock_guard<std::mutex> mutex(mutex_);
    eventMap_.erase(typeId);
}

std::optional<WebSocketCallback> CJWebsocketProxy::FindCallback(int32_t typeId)
{
    std::lock_guard<std::mutex> mutex(mutex_);
    auto iter = eventMap_.find(typeId);
    if (iter != eventMap_.end()) {
        return iter->second;
    }

    return std::nullopt;
}
}