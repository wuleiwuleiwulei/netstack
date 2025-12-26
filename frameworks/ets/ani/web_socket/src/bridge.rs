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

use std::collections::HashMap;

use ani_rs::{business_error::BusinessError, typed_array::ArrayBuffer};
use serde::{Deserialize, Serialize};

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.Cleaner")]
pub struct AniCleaner {
    pub nativePtr: i64,
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.CleanerServer")]
pub struct AniCleanerServer {
    pub nativePtr: i64,
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.WebSocketInner")]
pub struct AniWebSocket {
    pub nativePtr: i64,
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.WebSocketServerInner")]
pub struct AniWebSocketServer {
    pub nativePtr: i64,
}

#[ani_rs::ani(path = "@ohos.net.connection.connection.HttpProxyInner")]
pub struct AniHttpProxy {
    pub host: String,

    pub port: i32,

    pub username: Option<String>,

    pub password: Option<String>,

    pub exclusion_list: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub enum AniProxyConfiguration {
    S(String),
    #[serde(rename = "@ohos.net.connection.connection.HttpProxyInner")]
    Proxy(AniHttpProxy),
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.WebSocketRequestOptionsInner")]
pub struct AniWebSocketRequestOptions {
    pub header: Option<HashMap<String, String>>,

    pub caPath: Option<String>,

    pub clientCert: Option<AniClientCert>,

    pub proxy: Option<AniProxyConfiguration>,
    pub protocol: Option<String>,
}

impl AniWebSocketRequestOptions {
    pub fn new() -> Self {
        Self {
            header: None,
            caPath: None,
            clientCert: None,
            proxy: None,
            protocol: None,
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.ClientCertInner")]
pub struct AniClientCert {
    pub certPath: String,

    pub keyPath: String,

    pub keyPassword: Option<String>,
}

impl AniClientCert {
    pub fn new() -> Self {
        Self {
            certPath: "".to_string(),
            keyPath: "".to_string(),
            keyPassword: None,
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.CloseResultInner")]
pub struct AniCloseResult {
    pub code: i32,
    pub reason: String,
}

impl AniCloseResult {
    pub fn new() -> Self {
        Self {
            code: 0,
            reason: "".to_string(),
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.OpenResultInner")]
pub struct AniOpenResult {
    pub status: i32,
    pub message: String,
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.WebSocketCloseOptionsInner")]
pub struct AniWebSocketCloseOptions {
    pub code: Option<i32>,
    pub reason: Option<String>,
}

impl AniWebSocketCloseOptions {
    pub fn new() -> Self {
        Self {
            code: None,
            reason: None,
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.ServerCertInner")]
pub struct AniServerCert {
    pub certPath: String,
    pub keyPath: String,
}

impl AniServerCert {
    pub fn new() -> Self {
        Self {
            certPath: "".to_string(),
            keyPath: "".to_string(),
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.WebSocketServerConfigInner")]
pub struct AniWebSocketServerConfig {
    pub serverIP: Option<String>,
    pub serverPort: i32,
    pub serverCert: Option<AniServerCert>,
    pub maxConcurrentClientsNumber: i32,
    pub protocol: Option<String>,
    pub maxConnectionsForOneClient: i32,
}

impl AniWebSocketServerConfig {
    pub fn new() -> Self {
        Self {
            serverIP: None,
            serverPort: 0,
            serverCert: None,
            maxConcurrentClientsNumber: 0,
            protocol: None,
            maxConnectionsForOneClient: 0,
        }
    }
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.WebSocketConnectionInner")]
pub struct AniWebSocketConnection {
    pub clientIP: String,
    pub clientPort: i32,
}

impl AniWebSocketConnection {
    pub fn new() -> Self {
        Self {
            clientIP: "".to_string(),
            clientPort: 0,
        }
    }
}

pub fn get_web_socket_connection_client_ip(conn: &AniWebSocketConnection) -> String {
    conn.clientIP.clone()
}

pub fn get_web_socket_connection_client_port(conn: &AniWebSocketConnection) -> i32 {
    conn.clientPort.clone()
}

pub fn socket_connection_push_data(
    connection_info_value: &mut Vec<AniWebSocketConnection>,
    clientIP: String,
    clientPort: i32,
) {
    let connection_info = AniWebSocketConnection {clientIP, clientPort};
    connection_info_value.push(connection_info);
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.ResponseHeaders")]
pub enum AniResponseHeaders {
    MapBuffer(HashMap<String, String>),
    VecBuffer(Vec<String>),
    Undefined,
}

#[derive(Serialize, Deserialize)]
pub enum AniData {
    S(String),
    ArrayBuffer(ArrayBuffer),
}

#[ani_rs::ani(path = "@ohos.net.webSocket.webSocket.WebSocketMessageInner")]
pub struct AniWebSocketMessage {
    pub data: AniData,
    pub clientConnection: AniWebSocketConnection,
}

impl AniWebSocketMessage {
    pub fn new(data: AniData, clientConnection: AniWebSocketConnection) -> Self {
        Self {
            data,
            clientConnection,
        }
    }
}

pub const fn convert_to_business_error(code: i32) -> BusinessError {
    match code {
        1004 => BusinessError::new_static(2302001, "Websocket url error"),
        1020 => BusinessError::PERMISSION,
        2302001 => BusinessError::new_static(2302001, "Websocket url error"),
        2302002 => BusinessError::new_static(2302002, "Websocket file not exist"),
        2302003 => BusinessError::new_static(2302003, "Websocket connection exist"),
        _ => BusinessError::new_static(code, "Unknown error"),
    }
}