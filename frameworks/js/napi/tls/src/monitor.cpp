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

#include "monitor.h"

#include <cstddef>
#include <utility>

#include <napi/native_api.h>
#include <napi/native_common.h>
#include <securec.h>
#include <uv.h>

#include "module_template.h"
#include "napi_utils.h"
#include "netstack_log.h"
#include "tls_socket.h"

namespace OHOS {
namespace NetStack {
namespace TlsSocket {
namespace {
constexpr int PARAM_OPTION = 1;
constexpr int PARAM_OPTION_CALLBACK = 2;
constexpr std::string_view EVENT_MESSAGE = "message";
constexpr std::string_view EVENT_CONNECT = "connect";
constexpr std::string_view EVENT_CLOSE = "close";
constexpr std::string_view EVENT_ERROR = "error";
constexpr std::initializer_list<std::string_view> EVENTS = {EVENT_MESSAGE, EVENT_CONNECT, EVENT_CLOSE, EVENT_ERROR};

constexpr const char *PROPERTY_ADDRESS = "address";
constexpr const char *PROPERTY_FAMILY = "family";
constexpr const char *PROPERTY_PORT = "port";
constexpr const char *PROPERTY_SIZE = "size";
constexpr const char *ON_MESSAGE = "message";
constexpr const char *ON_REMOTE_INFO = "remoteInfo";

void ParserNullBranch(const std::string &errMessage, uv_work_t *&work, UvWorkWrapperShared *&workWrapper)
{
    NETSTACK_LOGE("%{public}s", errMessage.c_str());
    if (workWrapper != nullptr) {
        delete workWrapper;
        workWrapper = nullptr;
    }

    if (work != nullptr) {
        delete work;
        work = nullptr;
    }
}

void SetPropertyForWorkWrapper(UvWorkWrapperShared *workWrapper, Monitor::MessageRecvParma *messageRecvParma,
                               napi_value arrayBuffer, napi_value remoteInfo, napi_value obj)
{
    napi_value message = nullptr;
    napi_create_typedarray(workWrapper->env, napi_uint8_array, messageRecvParma->data_.size(), arrayBuffer, 0,
                           &message);
    napi_value address = NapiUtils::CreateStringUtf8(workWrapper->env, messageRecvParma->remoteInfo_.GetAddress());
    napi_value family = NapiUtils::CreateStringUtf8(workWrapper->env, messageRecvParma->remoteInfo_.GetFamily());
    napi_value port = NapiUtils::CreateInt32(workWrapper->env, messageRecvParma->remoteInfo_.GetPort());
    napi_value size = NapiUtils::CreateInt32(workWrapper->env, messageRecvParma->remoteInfo_.GetSize());
    NapiUtils::SetNamedProperty(workWrapper->env, remoteInfo, PROPERTY_ADDRESS, address);
    NapiUtils::SetNamedProperty(workWrapper->env, remoteInfo, PROPERTY_FAMILY, family);
    NapiUtils::SetNamedProperty(workWrapper->env, remoteInfo, PROPERTY_PORT, port);
    NapiUtils::SetNamedProperty(workWrapper->env, remoteInfo, PROPERTY_SIZE, size);
    NapiUtils::SetNamedProperty(workWrapper->env, obj, ON_MESSAGE, message);
    NapiUtils::SetNamedProperty(workWrapper->env, obj, ON_REMOTE_INFO, remoteInfo);
}

void EventMessageCallback(uv_work_t *work, int status)
{
    (void)status;
    if (work == nullptr) {
        NETSTACK_LOGE("work is nullptr");
        return;
    }
    auto workWrapper = static_cast<UvWorkWrapperShared *>(work->data);
    auto eventManager = workWrapper->manager;
    auto messageRecvParam = reinterpret_cast<Monitor::MessageRecvParma *>(eventManager->GetQueueData());
    if (!messageRecvParam) {
        NETSTACK_LOGE("messageRecvParam is nullptr");
        return;
    }

    napi_env env = workWrapper->env;
    auto closeScope = [env](napi_handle_scope scope) { NapiUtils::CloseScope(env, scope); };
    std::unique_ptr<napi_handle_scope__, decltype(closeScope)> scope(NapiUtils::OpenScope(env), closeScope);

    napi_value obj = NapiUtils::CreateObject(workWrapper->env);
    napi_value remoteInfo = NapiUtils::CreateObject(workWrapper->env);
    void *data = nullptr;
    napi_value arrayBuffer = NapiUtils::CreateArrayBuffer(workWrapper->env, messageRecvParam->data_.size(), &data);
    if (data != nullptr && NapiUtils::ValueIsArrayBuffer(env, arrayBuffer) &&
        memcpy_s(data, messageRecvParam->data_.size(), messageRecvParam->data_.c_str(),
                 messageRecvParam->data_.size()) != EOK) {
        delete messageRecvParam;
        ParserNullBranch("", work, workWrapper);
        return;
    }
    SetPropertyForWorkWrapper(workWrapper, messageRecvParam, arrayBuffer, remoteInfo, obj);

    if (workWrapper->manager == nullptr) {
        delete messageRecvParam;
        ParserNullBranch("manager is invalid", work, workWrapper);
        return;
    }
    workWrapper->manager->Emit(workWrapper->type, std::make_pair(NapiUtils::GetUndefined(workWrapper->env), obj));
    delete messageRecvParam;
    ParserNullBranch("event message callback success", work, workWrapper);
}

void EventConnectCloseCallback(uv_work_t *work, int status)
{
    (void)status;
    if (work == nullptr) {
        NETSTACK_LOGE("work is nullptr");
        return;
    }
    auto workWrapper = static_cast<UvWorkWrapperShared *>(work->data);
    if (workWrapper == nullptr) {
        NETSTACK_LOGE("workWrapper is nullptr");
        delete work;
        return;
    }
    if (workWrapper->manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    napi_handle_scope scope = NapiUtils::OpenScope(workWrapper->env);
    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(workWrapper->env),
                                             NapiUtils::GetUndefined(workWrapper->env)};
    workWrapper->manager->Emit(workWrapper->type, arg);
    NapiUtils::CloseScope(workWrapper->env, scope);
    delete workWrapper;
    delete work;
}

void EventErrorCallback(uv_work_t *work, int status)
{
    (void)status;
    if (work == nullptr) {
        NETSTACK_LOGE("work is nullptr");
        return;
    }
    auto workWrapper = static_cast<UvWorkWrapperShared *>(work->data);
    if (workWrapper == nullptr) {
        NETSTACK_LOGE("workWrapper is nullptr");
        delete work;
        return;
    }
    std::shared_ptr<Monitor::ErrorRecvParma> errorRecvParma(static_cast<Monitor::ErrorRecvParma *>(workWrapper->data));
    if (errorRecvParma == nullptr) {
        NETSTACK_LOGE("monitor is nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    if (workWrapper->manager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        delete workWrapper;
        delete work;
        return;
    }
    napi_handle_scope scope = NapiUtils::OpenScope(workWrapper->env);
    napi_value obj = NapiUtils::CreateObject(workWrapper->env);
    napi_value errorNumber = NapiUtils::CreateInt32(workWrapper->env, errorRecvParma->errorNumber_);
    napi_value errorString = NapiUtils::CreateStringUtf8(workWrapper->env, errorRecvParma->errorString_);
    NapiUtils::SetNamedProperty(workWrapper->env, obj, "errorNumber", errorNumber);
    NapiUtils::SetNamedProperty(workWrapper->env, obj, "errorString", errorString);
    std::pair<napi_value, napi_value> arg = {NapiUtils::GetUndefined(workWrapper->env), obj};
    workWrapper->manager->Emit(workWrapper->type, arg);
    NapiUtils::CloseScope(workWrapper->env, scope);
    delete workWrapper;
    delete work;
}
} // namespace

Monitor::Monitor() {}

Monitor::~Monitor() {}

void Monitor::ParserEventForOn(const std::string event, const std::shared_ptr<TLSSocket> &tlsSocket,
                               const std::shared_ptr<EventManager> &manager)
{
    if (event == EVENT_MESSAGE) {
        AddEventMessage(tlsSocket, manager);
    }
    if (event == EVENT_CLOSE) {
        tlsSocket->OnClose([this, manager]() {
            if (manager != nullptr) {
                manager->EmitByUvWithoutCheckShared(std::string(EVENT_CLOSE), nullptr, EventConnectCloseCallback);
            }
        });
    }
    if (event == EVENT_CONNECT) {
        tlsSocket->OnConnect([this, manager]() {
            if (manager != nullptr) {
                manager->EmitByUvWithoutCheckShared(std::string(EVENT_CONNECT), nullptr, EventConnectCloseCallback);
            }
        });
    }
    if (event == EVENT_ERROR) {
        tlsSocket->OnError([this, manager](auto errorNumber, auto errorString) {
            if (manager != nullptr && manager->HasEventListener(std::string(EVENT_ERROR))) {
                ErrorRecvParma *errorRecvParma = new ErrorRecvParma();
                errorRecvParma->errorNumber_ = errorNumber;
                errorRecvParma->errorString_ = errorString;
                manager->EmitByUvWithoutCheckShared(std::string(EVENT_ERROR), static_cast<void *>(errorRecvParma),
                    EventErrorCallback);
            }
        });
    }
}

void Monitor::AddEventMessage(const std::shared_ptr<TLSSocket> &tlsSocket,
    const std::shared_ptr<EventManager> &manager) const
{
    if (tlsSocket == nullptr) {
        return;
    }
    tlsSocket->OnMessage([this, manager](auto data, auto remoteInfo) {
        if (manager != nullptr && manager->HasEventListener(std::string(EVENT_MESSAGE))) {
            auto messageRecvParma = new (std::nothrow) MessageRecvParma();
            if (messageRecvParma == nullptr) {
                return;
            }
            messageRecvParma->data_ = data;
            messageRecvParma->remoteInfo_ = remoteInfo;
            manager->SetQueueData(reinterpret_cast<void *>(messageRecvParma));
            manager->EmitByUvWithoutCheckShared(std::string(EVENT_MESSAGE), nullptr, EventMessageCallback);
        }
    });
}

napi_value Monitor::On(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));
    if (paramsCount == PARAM_OPTION) {
        return NapiUtils::GetUndefined(env);
    }
    if (paramsCount != PARAM_OPTION_CALLBACK) {
        if (NapiUtils::GetValueType(env, params[0]) != napi_string) {
            napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        }
        if (NapiUtils::GetValueType(env, params[1]) != napi_function) {
            return NapiUtils::GetUndefined(env);
        }
    }
    std::shared_ptr<EventManager> *sharedManager = nullptr;
    napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager));
    if (sharedManager == nullptr || *sharedManager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto manager = *sharedManager;
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocket = reinterpret_cast<std::shared_ptr<TLSSocket> *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("tlsSocket is null");
        return NapiUtils::GetUndefined(env);
    }
    auto shared = *tlsSocket;
    if (!shared) {
        return NapiUtils::GetUndefined(env);
    }
    lock.unlock();

    const std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    if (std::find(EVENTS.begin(), EVENTS.end(), event) == EVENTS.end()) {
        NETSTACK_LOGE("Incorrect listening event %{public}s", event.c_str());
        return NapiUtils::GetUndefined(env);
    }
    manager->AddListener(env, event, params[1], false, false);
    ParserEventForOn(event, shared, manager);
    return NapiUtils::GetUndefined(env);
}

void Monitor::ParserEventForOff(const std::string event, const std::shared_ptr<TLSSocket> &tlsSocket)
{
    if (event == EVENT_MESSAGE) {
        tlsSocket->OffMessage();
    }
    if (event == EVENT_CLOSE) {
        tlsSocket->OffClose();
    }
    if (event == EVENT_CONNECT) {
        tlsSocket->OffConnect();
    }
    if (event == EVENT_ERROR) {
        tlsSocket->OffError();
    }
}

napi_value Monitor::Off(napi_env env, napi_callback_info info)
{
    napi_value thisVal = nullptr;
    size_t paramsCount = MAX_PARAM_NUM;
    napi_value params[MAX_PARAM_NUM] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &paramsCount, params, &thisVal, nullptr));
    if (paramsCount == PARAM_OPTION) {
        return NapiUtils::GetUndefined(env);
    }

    if (paramsCount != PARAM_OPTION_CALLBACK) {
        if (NapiUtils::GetValueType(env, params[0]) != napi_string) {
            napi_throw_error(env, std::to_string(PARSE_ERROR_CODE).c_str(), PARSE_ERROR_MSG);
        }
        if (NapiUtils::GetValueType(env, params[1]) != napi_function) {
            return NapiUtils::GetUndefined(env);
        }
    }
    std::shared_ptr<EventManager> *sharedManager = nullptr;
    napi_unwrap(env, thisVal, reinterpret_cast<void **>(&sharedManager));
    if (sharedManager == nullptr || *sharedManager == nullptr) {
        NETSTACK_LOGE("manager is nullptr");
        return NapiUtils::GetUndefined(env);
    }
    auto manager = *sharedManager;
    std::shared_lock<std::shared_mutex> lock(manager->GetDataMutex());
    auto tlsSocket = reinterpret_cast<std::shared_ptr<TLSSocket> *>(manager->GetData());
    if (tlsSocket == nullptr) {
        NETSTACK_LOGE("tlsSocket is null");
        return NapiUtils::GetUndefined(env);
    }

    auto shared = *tlsSocket;
    if (!shared) {
        return NapiUtils::GetUndefined(env);
    }
    lock.unlock();
    const std::string event = NapiUtils::GetStringFromValueUtf8(env, params[0]);
    ParserEventForOff(event, shared);
    manager->DeleteListener(event);
    return NapiUtils::GetUndefined(env);
}
} // namespace TlsSocket
} // namespace NetStack
} // namespace OHOS
