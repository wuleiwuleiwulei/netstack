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

use core::str;
use std::ffi::CStr;

use ani_rs::{
    business_error::BusinessError,
    objects::{AniFnObject, AniErrorCallback, AniRef, GlobalRefCallback, GlobalRefAsyncCallback},
    AniEnv,
};

use crate::{
    bridge::{self, AniCleanerServer},
    wrapper::AniServer,
};

#[ani_rs::native]
pub(crate) fn web_socket_server_clean(this: AniCleanerServer) -> Result<(), BusinessError> {
    info!("Cleaning up WebSocket server");
    let _ = unsafe { Box::from_raw(this.nativePtr as *mut AniServer) };
    Ok(())
}

#[ani_rs::native]
pub fn create_web_socket_server<'local>(
    env: &AniEnv<'local>,
) -> Result<AniRef<'local>, BusinessError> {
    info!("Creating WebSocket server instance");
    static WEB_SOCKET_SERVER_CLASS: &CStr = unsafe {
        CStr::from_bytes_with_nul_unchecked(
            b"@ohos.net.webSocket.webSocket.WebSocketServerInner\0",
        )
    };
    static CTOR_SIGNATURE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"l:\0") };
    let ptr = AniServer::new();
    let class = env.find_class(WEB_SOCKET_SERVER_CLASS).unwrap();
    let obj = env
        .new_object_with_signature(&class, CTOR_SIGNATURE, (ptr,))
        .unwrap();
    Ok(obj.into())
}

#[ani_rs::native]
pub(crate) fn start_sync(
    this: bridge::AniWebSocketServer,
    config: bridge::AniWebSocketServerConfig,
) -> Result<bool, BusinessError> {
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };

    let server_ip_str = config.serverIP
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("0.0.0.0")
        .to_string();
    info!("Starting WebSocket server at IP: {}", server_ip_str);
    let server_port_num = config.serverPort;
    let server_cert_path = config.serverCert
        .as_ref()
        .map(|s| s.certPath.as_str())
        .unwrap_or("")
        .to_string();
    let server_key_path = config.serverCert
        .as_ref()
        .map(|s| s.keyPath.as_str())
        .unwrap_or("")
        .to_string();
    let max_con_current_client_num = config.maxConcurrentClientsNumber;
    let protocol_str = config.protocol
        .as_ref()
        .map(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    let max_connections_for_one_client_num = config.maxConnectionsForOneClient;

    web_socket_server
        .start(
            server_ip_str,
            server_port_num,
            server_cert_path,
            server_key_path,
            max_con_current_client_num,
            protocol_str,
            max_connections_for_one_client_num,
        )
        .map(|_| true)
        .map_err(|e| BusinessError::new(e, format!("Failed to start")))
}

#[ani_rs::native]
pub(crate) fn stop_sync(this: bridge::AniWebSocketServer) -> Result<bool, BusinessError> {
    info!("Stopping WebSocket server");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    web_socket_server
        .stop()
        .map(|_| true)
        .map_err(|e| BusinessError::new(e, format!("Failed to stop")))
}

#[ani_rs::native]
pub(crate) fn send_sync(
    this: bridge::AniWebSocketServer,
    data: bridge::AniData,
    connection: bridge::AniWebSocketConnection,
) -> Result<bool, BusinessError> {
    info!(
        "Sending data to connection ip: {} and port: {}",
        connection.clientIP, connection.clientPort
    );
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    let (s, data_type) = match data {
        bridge::AniData::S(s) => (s.into_bytes(), 0),
        bridge::AniData::ArrayBuffer(arr) => (arr.to_vec(), 1),
    };
    web_socket_server
        .send(s, &connection, data_type)
        .map(|_| true)
        .map_err(|e| {
            BusinessError::new(e, format!("Failed to send data to connection ip: {} and port: {}",
                connection.clientIP, connection.clientPort))
        })
}

#[ani_rs::native]
pub(crate) fn close_sync(
    this: bridge::AniWebSocketServer,
    connection: bridge::AniWebSocketConnection,
    options: Option<bridge::AniWebSocketCloseOptions>,
) -> Result<bool, BusinessError> {
    info!(
        "Closing connection ip: {} and port: {}",
        connection.clientIP, connection.clientPort
    );
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };

    let code = options.as_ref().and_then(|opt| opt.code).unwrap_or(0) as u32;
    let reason = options
        .as_ref()
        .and_then(|opt| opt.reason.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("");

    web_socket_server
        .close(&connection, code, &reason)
        .map(|_| true)
        .map_err(|e| {
            BusinessError::new(e, format!("Failed to close connection ip: {} and port: {}",
            connection.clientIP, connection.clientPort))})
}

#[ani_rs::native]
pub(crate) fn list_all_connections_sync(
    this: bridge::AniWebSocketServer,
) -> Result<Vec<bridge::AniWebSocketConnection>, BusinessError> {
    info!("Listing all WebSocket connections");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    let mut socket_connection = Vec::new();
    web_socket_server.list_all_connections(&mut socket_connection);
    Ok(socket_connection)
}

#[ani_rs::native]
pub(crate) fn on_error(
    env: &AniEnv,
    this: bridge::AniWebSocketServer,
    error_callback: AniErrorCallback,
) -> Result<(), BusinessError> {
    info!("Setting up error callback for WebSocket server");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    web_socket_server.callback.on_error = Some(error_callback.into_global_callback(env).unwrap());
    web_socket_server.on_error_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_error(
    env: &AniEnv,
    this: bridge::AniWebSocketServer,
    error_callback: AniErrorCallback,
) -> Result<(), BusinessError> {
    info!("Removing error callback for WebSocket server");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    web_socket_server.callback.on_error = None;
    web_socket_server.off_error_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_connect(
    env: &AniEnv,
    this: bridge::AniWebSocketServer,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    info!("Setting up connect callback for WebSocket server");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    web_socket_server.callback.on_connect = Some(callback.into_global_callback(env).unwrap());
    web_socket_server.on_connect_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_connect(
    env: &AniEnv,
    this: bridge::AniWebSocketServer,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    info!("Removing connect callback for WebSocket server");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    web_socket_server.callback.on_connect = None;
    web_socket_server.off_connect_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_close(
    env: &AniEnv,
    this: bridge::AniWebSocketServer,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    info!("Setting up close callback for WebSocket server");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    web_socket_server.callback.on_close = Some(callback.into_global_callback(env).unwrap());
    web_socket_server.on_close_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_close(
    env: &AniEnv,
    this: bridge::AniWebSocketServer,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    info!("Removing close callback for WebSocket server");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    web_socket_server.callback.on_close = None;
    web_socket_server.off_close_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_message_receive(
    env: &AniEnv,
    this: bridge::AniWebSocketServer,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    info!("add message receive callback for WebSocket server");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    web_socket_server.callback.on_message_receive = Some(callback.into_global_callback(env).unwrap());
    web_socket_server.on_message_receive_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_message_receive(
    env: &AniEnv,
    this: bridge::AniWebSocketServer,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    info!("Removing message receive callback for WebSocket server");
    let web_socket_server = unsafe { &mut *(this.nativePtr as *mut AniServer) };
    web_socket_server.callback.on_message_receive = None;
    web_socket_server.off_message_receive_native();
    Ok(())
}