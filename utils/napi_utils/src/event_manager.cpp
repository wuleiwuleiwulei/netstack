/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <map>

#include "event_manager.h"

#include "napi_utils.h"
#include "netstack_log.h"

namespace OHOS::NetStack {
static constexpr const int CALLBACK_PARAM_NUM = 1;
static constexpr const int ASYNC_CALLBACK_PARAM_NUM = 2;
static constexpr const int CALLBACK_TWO_PARAM_NUM = 2;
static constexpr const int ASYNC_CALLBACK_TWO_PARAM_NUM = 3;
static constexpr const char *ON_HEADER_RECEIVE = "headerReceive";
static constexpr const char *ON_HEADERS_RECEIVE = "headersReceive";

EventManager::EventManager() : data_(nullptr), eventRef_(nullptr), isDestroy_(false), proxyData_{nullptr} {}

EventManager::~EventManager()
{
    NETSTACK_LOGD("EventManager is destructed by the destructor");
}

void EventManager::AddListener(napi_env env, const std::string &type, napi_value callback, bool once,
                               bool asyncCallback)
{
    std::unique_lock<std::shared_mutex> lock(mutexForListenersAndEmitByUv_);
    auto it = std::remove_if(listeners_.begin(), listeners_.end(),
        [type](const std::shared_ptr<EventListener> &listener) -> bool { return listener->MatchType(type); });
    if (it != listeners_.end()) {
        listeners_.erase(it, listeners_.end());
    }
    auto listener = std::make_shared<EventListener>(GetCurrentThreadId(), env, type, callback, once, asyncCallback);
    listeners_.emplace_back(std::move(listener));
}

void EventManager::DeleteListener(const std::string &type, napi_value callback)
{
    std::unique_lock<std::shared_mutex> lock(mutexForListenersAndEmitByUv_);
    auto it = std::remove_if(listeners_.begin(), listeners_.end(),
        [type, callback] (const std::shared_ptr<EventListener> &listener) -> bool {
            return listener->Match(type, callback);
        });
    listeners_.erase(it, listeners_.end());
}

void EventManager::Emit(const std::string &type, const std::pair<napi_value, napi_value> &argv)
{
    std::shared_lock<std::shared_mutex> lock(mutexForListenersAndEmitByUv_);
    auto listeners = listeners_;
    lock.unlock();
    std::for_each(listeners.begin(), listeners.end(), [type, argv] (const std::shared_ptr<EventListener> &listener) {
        if (listener->IsAsyncCallback()) {
            /* AsyncCallback(BusinessError error, T data) */
            napi_value arg[ASYNC_CALLBACK_PARAM_NUM] = {argv.first, argv.second};
            listener->Emit(type, ASYNC_CALLBACK_PARAM_NUM, arg);
        } else {
            /* Callback(T data) */
            napi_value arg[CALLBACK_PARAM_NUM] = {argv.second};
            listener->Emit(type, CALLBACK_PARAM_NUM, arg);
        }
    });
    std::unique_lock<std::shared_mutex> lock2(mutexForListenersAndEmitByUv_);
    auto it = std::remove_if(listeners_.begin(), listeners_.end(),
        [type] (const std::shared_ptr<EventListener> &listener) -> bool { return listener->MatchOnce(type); });
    listeners_.erase(it, listeners_.end());
}

void EventManager::EmitWithTwoPara(const std::string &type, const std::tuple<napi_value, napi_value, napi_value> &argv)
{
    std::shared_lock<std::shared_mutex> lock(mutexForListenersAndEmitByUv_);
    auto listeners = listeners_;
    lock.unlock();
    std::for_each(listeners.begin(), listeners.end(), [type, argv] (const std::shared_ptr<EventListener> &listener) {
        if (listener->IsAsyncCallback()) {
            /* AsyncCallback(BusinessError error, T data) */
            napi_value arg[ASYNC_CALLBACK_TWO_PARAM_NUM] = {std::get<0>(argv), std::get<1>(argv), std::get<2>(argv)};
            listener->Emit(type, ASYNC_CALLBACK_TWO_PARAM_NUM, arg);
        } else {
            /* Callback(T data) */
            napi_value arg[CALLBACK_TWO_PARAM_NUM] = {std::get<1>(argv), std::get<2>(argv)};
            listener->Emit(type, CALLBACK_TWO_PARAM_NUM, arg);
        }
    });
    std::unique_lock<std::shared_mutex> lock2(mutexForListenersAndEmitByUv_);
    auto it = std::remove_if(listeners_.begin(), listeners_.end(),
        [type] (const std::shared_ptr<EventListener> &listener) -> bool { return listener->MatchOnce(type); });
    listeners_.erase(it, listeners_.end());
}

void EventManager::SetData(void *data)
{
    data_ = data;
}

void *EventManager::GetData()
{
    return data_;
}

void EventManager::EmitByUvWithoutCheckShared(const std::string &type, void *data, void (*Handler)(uv_work_t *, int))
{
    std::shared_lock<std::shared_mutex> lock(mutexForListenersAndEmitByUv_);
    bool foundHeader = std::find_if(listeners_.begin(), listeners_.end(),
        [] (const std::shared_ptr<EventListener> &listener) { return listener->MatchType(ON_HEADER_RECEIVE); }) !=
        listeners_.end();

    bool foundHeaders = std::find_if(listeners_.begin(), listeners_.end(),
        [] (const std::shared_ptr<EventListener> &listener) { return listener->MatchType(ON_HEADERS_RECEIVE);}) !=
        listeners_.end();

    if (!foundHeader && !foundHeaders) {
        if (type == ON_HEADER_RECEIVE || type == ON_HEADERS_RECEIVE) {
            auto tempMap = static_cast<std::map<std::string, std::string> *>(data);
            delete tempMap;
            return;
        }
    } else if (foundHeader && !foundHeaders) {
        if (type == ON_HEADERS_RECEIVE) {
            auto tempMap = static_cast<std::map<std::string, std::string> *>(data);
            delete tempMap;
            return;
        }
    } else if (!foundHeader) {
        if (type == ON_HEADER_RECEIVE) {
            auto tempMap = static_cast<std::map<std::string, std::string> *>(data);
            delete tempMap;
            return;
        }
    }

    std::for_each(listeners_.begin(), listeners_.end(),
        [type, data, Handler, this] (const std::shared_ptr<EventListener> &listener) {
            if (listener->MatchType(type) && listener->GetCallbackRef() != nullptr) {
                auto workWrapper = new UvWorkWrapperShared(data, listener->GetEnv(), type, shared_from_this());
                NapiUtils::CreateUvQueueWork(listener->GetEnv(), workWrapper, Handler);
            }
        });
}

void EventManager::EmitWithoutUV(const std::string &type, void *data,
    napi_value (*MakeJsValue)(napi_env, const std::shared_ptr<EventManager> &))
{
    std::shared_lock<std::shared_mutex> lock(mutexForListenersAndEmitByUv_);
    std::for_each(listeners_.begin(), listeners_.end(),
        [type, data, MakeJsValue, this] (const std::shared_ptr<EventListener> &listener) {
            if (!listener->MatchType(type) || listener->GetCallbackRef() == nullptr) {
                return;
            }
            napi_env env = listener->GetEnv();
            if (!NapiUtils::IsEnvValid(env)) {
                NETSTACK_LOGE("the env is invalid");
                return;
            }
            
            auto manager = shared_from_this();
            auto task = [env, data, MakeJsValue, type, manager]() {
                if (!manager || !MakeJsValue) {
                    NETSTACK_LOGE("manager or handler is null");
                    return;
                }
                auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
                std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);
                napi_value obj = MakeJsValue(env, manager);
                std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(env), obj};
                manager->Emit(type, arg);
            };
            napi_status ret = napi_send_event(env, task, napi_eprio_immediate, type.c_str());
            if (ret != napi_ok) {
                NETSTACK_LOGE("napi_send_event error = %{public}d, manual delete", ret);
            }
        });
}

void EventManager::SetQueueData(void *data)
{
    std::lock_guard<std::mutex> lock(dataQueueMutex_);
    dataQueue_.push(data);
}

void *EventManager::GetQueueData()
{
    std::lock_guard<std::mutex> lock(dataQueueMutex_);
    if (!dataQueue_.empty()) {
        auto data = dataQueue_.front();
        dataQueue_.pop();
        return data;
    }
    NETSTACK_LOGE("eventManager data queue is empty");
    return nullptr;
}

void EventManager::SetServerQueueData(void *wsi, void *data)
{
    std::unique_lock<std::shared_mutex> lock(dataServerQueueMutex_);
    serverDataQueue_[wsi].push(data);
}

void *EventManager::GetServerQueueData(void *wsi)
{
    if (wsi == nullptr) {
        NETSTACK_LOGE("wsi is nullptr");
        return nullptr;
    }
    {
        std::shared_lock<std::shared_mutex> lock(dataServerQueueMutex_);
        if (serverDataQueue_.empty() || serverDataQueue_.find(wsi) == serverDataQueue_.end()) {
            NETSTACK_LOGE("eventManager server data queue is empty");
            return nullptr;
        }
        auto data = serverDataQueue_[wsi].front();
        serverDataQueue_[wsi].pop();
        return data;
    }
}

bool EventManager::HasEventListener(const std::string &type)
{
    std::shared_lock<std::shared_mutex> lock(mutexForListenersAndEmitByUv_);
    return std::any_of(listeners_.begin(), listeners_.end(),
        [&type] (const std::shared_ptr<EventListener> &listener) -> bool { return listener->MatchType(type); });
}

void EventManager::DeleteListener(const std::string &type)
{
    std::unique_lock<std::shared_mutex> lock(mutexForListenersAndEmitByUv_);
    auto it = std::remove_if(listeners_.begin(), listeners_.end(),
        [type] (const std::shared_ptr<EventListener> &listener) -> bool { return listener->MatchType(type); });
    listeners_.erase(it, listeners_.end());
}

std::mutex EventManager::mutexForManager_;
EventManagerMagic EventManager::magic_;

void EventManager::CreateEventReference(napi_env env, napi_value value)
{
    if (env != nullptr && value != nullptr) {
        eventRef_ = NapiUtils::CreateReference(env, value);
    }
}

void EventManager::DeleteEventReference(napi_env env)
{
    if (env != nullptr && eventRef_ != nullptr) {
        NapiUtils::DeleteReference(env, eventRef_);
    }
    eventRef_ = nullptr;
}

void EventManager::SetEventDestroy(bool flag)
{
    isDestroy_.store(flag);
}

bool EventManager::IsEventDestroy()
{
    return isDestroy_.load();
}

const std::string &EventManager::GetWebSocketTextData()
{
    return webSocketTextData_;
}

void EventManager::AppendWebSocketTextData(void *data, size_t length)
{
    webSocketTextData_.append(reinterpret_cast<char *>(data), length);
}

const std::string &EventManager::GetWebSocketBinaryData()
{
    return webSocketBinaryData_;
}

void EventManager::AppendWebSocketBinaryData(void *data, size_t length)
{
    webSocketBinaryData_.append(reinterpret_cast<char *>(data), length);
}

const std::string &EventManager::GetWsServerBinaryData(void *wsi)
{
    return wsServerBinaryData_[wsi];
}

const std::string &EventManager::GetWsServerTextData(void *wsi)
{
    return wsServerTextData_[wsi];
}

void EventManager::AppendWsServerBinaryData(void *wsi, void *data, size_t length)
{
    wsServerBinaryData_[wsi].append(reinterpret_cast<char *>(data), length);
}

void EventManager::AppendWsServerTextData(void *wsi, void *data, size_t length)
{
    wsServerTextData_[wsi].append(reinterpret_cast<char *>(data), length);
}

void EventManager::ClearWsServerBinaryData(void *wsi)
{
    wsServerBinaryData_[wsi].clear();
}

void EventManager::ClearWsServerTextData(void *wsi)
{
    wsServerTextData_[wsi].clear();
}

void EventManager::SetMaxConnClientCnt(const uint32_t &cnt)
{
    maxConnClientCnt_ = cnt;
}

void EventManager::SetMaxConnForOneClient(const uint32_t &cnt)
{
    maxConnForOneClient_ = cnt;
}

uint32_t EventManager::GetMaxConcurrentClientCnt() const
{
    return maxConnClientCnt_;
}

uint32_t EventManager::GetMaxConnForOneClient() const
{
    return maxConnForOneClient_;
}

void EventManager::AddClientUserData(void *wsi, std::shared_ptr<Websocket::UserData> &data)
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    userDataMap_[wsi] = data;
}

void EventManager::RemoveClientUserData(void *wsi)
{
    std::lock_guard<std::mutex> lock(mapMutex_);
    auto it = userDataMap_.find(wsi);
    if (it != userDataMap_.end()) {
        userDataMap_.erase(it);
    }
}

void EventManager::ClearWebSocketTextData()
{
    webSocketTextData_.clear();
}

void EventManager::ClearWebSocketBinaryData()
{
    webSocketBinaryData_.clear();
}

std::shared_mutex &EventManager::GetDataMutex()
{
    return dataMutex_;
}

void EventManager::NotifyRcvThdExit()
{
    std::unique_lock<std::mutex> lock(sockRcvThdMtx_);
    sockRcvExit_ = true;
    sockRcvThdCon_.notify_one();
}

void EventManager::WaitForRcvThdExit()
{
    std::unique_lock<std::mutex> lock(sockRcvThdMtx_);
    sockRcvThdCon_.wait(lock, [this]() { return sockRcvExit_; });
}

void EventManager::SetReuseAddr(bool reuse)
{
    isReuseAddr_.store(reuse);
}

bool EventManager::GetReuseAddr()
{
    return isReuseAddr_.load();
}

void EventManager::SetContextState(bool enable)
{
    isOpened_ = enable;
}

bool EventManager::GetContextState()
{
    return isOpened_;
}

std::shared_ptr<Socks5::Socks5Instance> EventManager::GetProxyData()
{
    return proxyData_;
}

void EventManager::SetProxyData(std::shared_ptr<Socks5::Socks5Instance> data)
{
    proxyData_ = data;
}

void EventManager::SetWebSocketUserData(const std::shared_ptr<Websocket::UserData> &userData)
{
    std::unique_lock<std::shared_mutex> lock(webSocketUserDataMutex_);
    webSocketUserData_ = userData;
}

std::shared_ptr<Websocket::UserData> EventManager::GetWebSocketUserData()
{
    std::shared_lock<std::shared_mutex> lock(webSocketUserDataMutex_);
    return webSocketUserData_;
}

void EventManager::SetSocketConfig(const std::shared_ptr<Socket::SocketExec::SocketConfig> &config)
{
    socketConfig_ = config;
}

std::shared_ptr<Socket::SocketExec::SocketConfig> EventManager::GetSocketConfig()
{
    return socketConfig_;
}

UvWorkWrapperShared::UvWorkWrapperShared(void *theData, napi_env theEnv, std::string eventType,
                                         const std::shared_ptr<EventManager> &eventManager)
    : data(theData), env(theEnv), type(std::move(eventType)), manager(eventManager)
{
}
} // namespace OHOS::NetStack
