// Copyright (C) 2025 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const LOG_LABEL: hilog_rust::HiLogLabel = hilog_rust::HiLogLabel {
    log_type: hilog_rust::LogType::LogCore,
    domain: 0xD0015B0,
    tag: "WebSocketAni",
};

#[macro_use]
extern crate netstack_common;

mod bridge;
mod web_socket;
mod web_socket_server;
mod wrapper;

ani_rs::ani_constructor! {
    namespace "@ohos.net.webSocket.webSocket"
    [
        "createWebSocket" : web_socket::create_web_socket,
        "createWebSocketServer" : web_socket_server::create_web_socket_server,
    ]
    class "@ohos.net.webSocket.webSocket.WebSocketInner"
    [
        "connectSync" : web_socket::connect_sync,
        "sendSync" : web_socket::send_sync,
        "closeSync" : web_socket::close_sync,
        "onOpenInner" : web_socket::on_open,
        "onMessageInner" : web_socket::on_message,
        "onCloseInner" : web_socket::on_close,
        "onErrorInner" : web_socket::on_error,
        "onDataEndInner" : web_socket::on_data_end,
        "onHeaderReceiveInner" : web_socket::on_header_receive,
        "offOpenInner" : web_socket::off_open,
        "offMessageInner" : web_socket::off_message,
        "offCloseInner" : web_socket::off_close,
        "offErrorInner" : web_socket::off_error,
        "offDataEndInner" : web_socket::off_data_end,
        "offHeaderReceiveInner" : web_socket::off_header_receive,
    ]
    class "@ohos.net.webSocket.webSocket.WebSocketServerInner"
    [
        "startSync" : web_socket_server::start_sync,
        "stopSync" : web_socket_server::stop_sync,
        "sendSync" : web_socket_server::send_sync,
        "closeSync" : web_socket_server::close_sync,
        "listAllConnectionsSync" : web_socket_server::list_all_connections_sync,
        "onWebSocketServerErrorInner" : web_socket_server::on_error,
        "onConnectInner" : web_socket_server::on_connect,
        "onWebSocketServerCloseInner" : web_socket_server::on_close,
        "onMessageReceiveInner" : web_socket_server::on_message_receive,
        "offWebSocketServerErrorInner" : web_socket_server::off_error,
        "offConnectInner" : web_socket_server::off_connect,
        "offWebSocketServerCloseInner" : web_socket_server::off_close,
        "offMessageReceiveInner" : web_socket_server::off_message_receive,
    ]
    class "@ohos.net.webSocket.webSocket.Cleaner"
    [
        "clean" : web_socket::web_socket_clean,
    ]
    class "@ohos.net.webSocket.webSocket.CleanerServer"
    [
        "clean" : web_socket_server::web_socket_server_clean,
    ]
}

#[used]
#[link_section = ".init_array"]
static WEBSOCKET_PANIC_HOOK: extern "C" fn() = {
    #[link_section = ".text.startup"]
    extern "C" fn init() {
        std::panic::set_hook(Box::new(|info| {
            error!("Panic occurred: {:?}", info);
        }));
    }
    init
};
