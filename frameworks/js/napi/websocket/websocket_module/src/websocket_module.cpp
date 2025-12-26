/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "websocket_module.h"

#include "constant.h"
#include "netstack_log.h"
#include "module_template.h"
#include "netstack_common_utils.h"
#include "websocket_async_work.h"
#include "websocket_exec_common.h"

namespace OHOS::NetStack::Websocket {
static bool g_appIsAtomicService = false;
static std::once_flag g_isAtomicServiceFlag;
static std::string g_appBundleName;

napi_value WebSocketModule::InitWebSocketModule(napi_env env, napi_value exports)
{
    DefineWebSocketClass(env, exports);
#ifdef NETSTACK_WEBSOCKETSERVER
    DefineWebSocketServerClass(env, exports);
#endif
    InitWebSocketProperties(env, exports);
    NapiUtils::SetEnvValid(env);
    std::call_once(g_isAtomicServiceFlag, []() {
        g_appIsAtomicService = CommonUtils::IsAtomicService(g_appBundleName);
        NETSTACK_LOGI("IsAtomicService  bundleName is %{public}s, isAtomicService is %{public}d",
            g_appBundleName.c_str(), g_appIsAtomicService);
    });
    auto envWrapper = new (std::nothrow)napi_env;
    if (envWrapper == nullptr) {
        return exports;
    }
    *envWrapper = env;
    napi_add_env_cleanup_hook(env, NapiUtils::HookForEnvCleanup, envWrapper);
    return exports;
}

napi_value WebSocketModule::CreateWebSocket(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_WEB_SOCKET, FinalizeWebSocketInstance);
}

napi_value WebSocketModule::CreateWebSocketServer(napi_env env, napi_callback_info info)
{
#ifdef NETSTACK_WEBSOCKETSERVER
    return ModuleTemplate::NewInstanceWithSharedManager(env, info, INTERFACE_WEB_SOCKET_SERVER,
        FinalizeWebSocketInstance);
#else
    return nullptr;
#endif
}

void WebSocketModule::DefineWebSocketClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(WebSocket::FUNCTION_CONNECT, WebSocket::Connect),
        DECLARE_NAPI_FUNCTION(WebSocket::FUNCTION_SEND, WebSocket::Send),
        DECLARE_NAPI_FUNCTION(WebSocket::FUNCTION_CLOSE, WebSocket::Close),
        DECLARE_NAPI_FUNCTION(WebSocket::FUNCTION_ON, WebSocket::On),
        DECLARE_NAPI_FUNCTION(WebSocket::FUNCTION_OFF, WebSocket::Off),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_WEB_SOCKET);
}

#ifdef NETSTACK_WEBSOCKETSERVER
void WebSocketModule::DefineWebSocketServerClass(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(WebSocketServer::FUNCTION_START, WebSocketServer::Start),
        DECLARE_NAPI_FUNCTION(WebSocketServer::FUNCTION_LISTALLCONNECTIONS, WebSocketServer::ListAllConnections),
        DECLARE_NAPI_FUNCTION(WebSocketServer::FUNCTION_CLOSE, WebSocketServer::Close),
        DECLARE_NAPI_FUNCTION(WebSocketServer::FUNCTION_ON, WebSocketServer::On),
        DECLARE_NAPI_FUNCTION(WebSocketServer::FUNCTION_OFF, WebSocketServer::Off),
        DECLARE_NAPI_FUNCTION(WebSocketServer::FUNCTION_SEND, WebSocketServer::Send),
        DECLARE_NAPI_FUNCTION(WebSocketServer::FUNCTION_STOP, WebSocketServer::Stop),
    };
    ModuleTemplate::DefineClass(env, exports, properties, INTERFACE_WEB_SOCKET_SERVER);
}
#endif

void WebSocketModule::InitWebSocketProperties(napi_env env, napi_value exports)
{
    std::initializer_list<napi_property_descriptor> properties = {
        DECLARE_NAPI_FUNCTION(FUNCTION_CREATE_WEB_SOCKET, CreateWebSocket),
        DECLARE_NAPI_FUNCTION(FUNCTION_CREATE_WEB_SOCKET_SERVER, CreateWebSocketServer),
    };
    NapiUtils::DefineProperties(env, exports, properties);
}

void WebSocketModule::FinalizeWebSocketInstance(napi_env env, void *data, void *hint)
{
    NETSTACK_LOGI("websocket handle is finalized");
    auto sharedManager = reinterpret_cast<std::shared_ptr<EventManager> *>(data);
    if (sharedManager == nullptr) {
        return;
    }
    auto manager = *sharedManager;
    if (manager->GetWebSocketUserData() == nullptr) {
        return;
    }
    auto userData = manager->GetWebSocketUserData();
    userData->SetThreadStop(true);
    delete sharedManager;
}

napi_value WebSocketModule::WebSocket::Connect(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ConnectContext>(
        env, info, "WebSocketConnect",
        [](napi_env, napi_value, ConnectContext *context) -> bool {
            context->SetAtomicService(g_appIsAtomicService);
            context->SetBundleName(g_appBundleName);
            return true;
        },
        WebSocketAsyncWork::ExecConnect, WebSocketAsyncWork::ConnectCallback);
}

napi_value WebSocketModule::WebSocket::Send(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<SendContext>(
        env, info, "WebSocketSend", nullptr, WebSocketAsyncWork::ExecSend, WebSocketAsyncWork::SendCallback);
}

napi_value WebSocketModule::WebSocket::Close(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<CloseContext>(
        env, info, "WebSocketClose", nullptr, WebSocketAsyncWork::ExecClose, WebSocketAsyncWork::CloseCallback);
}

napi_value WebSocketModule::WebSocket::On(napi_env env, napi_callback_info info)
{
    ModuleTemplate::OnSharedManager(env, info,
                                    {EventName::EVENT_OPEN, EventName::EVENT_MESSAGE, EventName::EVENT_CLOSE}, true);
    return ModuleTemplate::OnSharedManager(
        env, info, {EventName::EVENT_ERROR, EventName::EVENT_HEADER_RECEIVE, EventName::EVENT_DATA_END}, false);
}

napi_value WebSocketModule::WebSocket::Off(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OffSharedManager(env, info,
                                            {EventName::EVENT_OPEN, EventName::EVENT_MESSAGE, EventName::EVENT_CLOSE,
                                             EventName::EVENT_ERROR, EventName::EVENT_DATA_END,
                                             EventName::EVENT_HEADER_RECEIVE});
}

#ifdef NETSTACK_WEBSOCKETSERVER
napi_value WebSocketModule::WebSocketServer::Start(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ServerStartContext>(
        env, info, "WebSocketServerStart", nullptr, WebSocketAsyncWork::ExecServerStart,
            WebSocketAsyncWork::ServerStartCallback);
}
 
napi_value WebSocketModule::WebSocketServer::ListAllConnections(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ListAllConnectionsContext>(
        env, info, "WebSocketServerListAllConnections", nullptr, WebSocketAsyncWork::ExecListAllConnections,
            WebSocketAsyncWork::ListAllConnectionsCallback);
}

napi_value WebSocketModule::WebSocketServer::Close(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ServerCloseContext>(
        env, info, "WebSocketServerClose", nullptr, WebSocketAsyncWork::ExecServerClose,
            WebSocketAsyncWork::ServerCloseCallback);
}

napi_value WebSocketModule::WebSocketServer::Send(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ServerSendContext>(
        env, info, "WebSocketServerSend", nullptr, WebSocketAsyncWork::ExecServerSend,
            WebSocketAsyncWork::ServerSendCallback);
}
 
napi_value WebSocketModule::WebSocketServer::Stop(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::InterfaceWithSharedManager<ServerStopContext>(
        env, info, "WebSocketServerStop", nullptr, WebSocketAsyncWork::ExecServerStop,
            WebSocketAsyncWork::ServerStopCallback);
}

napi_value WebSocketModule::WebSocketServer::On(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OnSharedManager(env, info,
        {EventName::EVENT_SERVER_CONNECT, EventName::EVENT_SERVER_MESSAGE_RECEIVE,
        EventName::EVENT_SERVER_ERROR, EventName::EVENT_SERVER_CLOSE}, false);
}
 
napi_value WebSocketModule::WebSocketServer::Off(napi_env env, napi_callback_info info)
{
    return ModuleTemplate::OffSharedManager(env, info,
        {EventName::EVENT_SERVER_ERROR, EventName::EVENT_SERVER_CONNECT,
         EventName::EVENT_SERVER_CLOSE, EventName::EVENT_SERVER_MESSAGE_RECEIVE});
}
#endif

static napi_module g_websocketModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = WebSocketModule::InitWebSocketModule,
    .nm_modname = "net.webSocket",
    .nm_priv = nullptr,
    .reserved = {nullptr},
};

extern "C" __attribute__((constructor)) void RegisterWebSocketModule(void)
{
    napi_module_register(&g_websocketModule);
}
} // namespace OHOS::NetStack::Websocket
