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
use std::pin::Pin;
use std::sync::{Mutex, OnceLock};

use ani_rs::{
    business_error::BusinessError,
    objects::{GlobalRefCallback, GlobalRefAsyncCallback, GlobalRefErrorCallback},
    AniEnv,
};

use crate::bridge::{
    get_web_socket_connection_client_ip, get_web_socket_connection_client_port,
    socket_connection_push_data, AniClientCert, AniCloseResult, AniOpenResult,
    AniWebSocketConnection, AniWebSocketMessage, AniData, AniResponseHeaders,
};


static WS_MAP_CLIENT: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();

fn get_ws_client_map() -> &'static Mutex<HashMap<usize, usize>> {
    WS_MAP_CLIENT.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn on_open_websocket_client(client: Pin<&mut ffi::WebSocketClientWrapper>, message: String, status: u32) {
    let client_ptr = &*client as *const _ as *mut ffi::WebSocketClientWrapper as usize;
    if let Some(&ws_ptr) = get_ws_client_map().lock().unwrap().get(&client_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniClient) };
        if let Some(cb) = &ws.callback.on_open {
            let cr = AniOpenResult {
                status: status as i32,
                message: message,
            };
            cb.execute((cr,));
        }
    }
}

pub fn on_message_websocket_client(client: Pin<&mut ffi::WebSocketClientWrapper>, data: String, len: u32) {
    let client_ptr = &*client as *const _ as *mut ffi::WebSocketClientWrapper as usize;
    if let Some(&ws_ptr) = get_ws_client_map().lock().unwrap().get(&client_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniClient) };
        if let Some(cb) = &ws.callback.on_message {
            let message = AniData::S(data);
            cb.execute(None, (message,));
        }
    }
}

pub fn on_close_websocket_client(client: Pin<&mut ffi::WebSocketClientWrapper>, reason: String, code: u32) {
    let client_ptr = &*client as *const _ as *mut ffi::WebSocketClientWrapper as usize;
    if let Some(&ws_ptr) = get_ws_client_map().lock().unwrap().get(&client_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniClient) };
        if let Some(cb) = &ws.callback.on_close {
            let cr = AniCloseResult {
                code: code as i32,
                reason: reason,
            };
            cb.execute(None, (cr,));
        }
    }
}

pub fn on_error_websocket_client(client: Pin<&mut ffi::WebSocketClientWrapper>, errMessage: String, errCode: u32) {
    let client_ptr = &*client as *const _ as *mut ffi::WebSocketClientWrapper as usize;
    if let Some(&ws_ptr) = get_ws_client_map().lock().unwrap().get(&client_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniClient) };
        if let Some(cb) = &ws.callback.on_error {
            let err = BusinessError::new(errCode as i32, errMessage);
            cb.execute(err);
        }
    }
}

pub fn on_data_end_websocket_client(client: Pin<&mut ffi::WebSocketClientWrapper>) {
    let client_ptr = &*client as *const _ as *mut ffi::WebSocketClientWrapper as usize;
    if let Some(&ws_ptr) = get_ws_client_map().lock().unwrap().get(&client_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniClient) };
        if let Some(cb) = &ws.callback.on_data_end {
            cb.execute(());
        }
    }
}

pub fn on_header_receive_websocket_client(client: Pin<&mut ffi::WebSocketClientWrapper>, keys: &mut Vec<String>,
                                          values: &mut Vec<String>) {
    let client_ptr = &*client as *const _ as *mut ffi::WebSocketClientWrapper as usize;
    if let Some(&ws_ptr) = get_ws_client_map().lock().unwrap().get(&client_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniClient) };
        if let Some(cb) = &ws.callback.on_header_receive {
            let mut data = HashMap::new();
            for (key, value) in keys.iter().zip(values.iter()) {
                data.insert(key.clone(), value.clone());
            }
            let map_headers = AniResponseHeaders::MapBuffer(data);
            cb.execute((map_headers,));
        }
    }
}

pub fn header_push_data(header: &mut Vec<String>, data: String)
{
    header.push(data);
}

pub struct CallBackWebSocketClient {
    pub on_open: Option<GlobalRefCallback<(AniOpenResult,)>>,
    pub on_message: Option<GlobalRefAsyncCallback<(AniData,)>>,
    pub on_close: Option<GlobalRefAsyncCallback<(AniCloseResult,)>>,
    pub on_error: Option<GlobalRefErrorCallback>,
    pub on_data_end: Option<GlobalRefCallback<()>>,
    pub on_header_receive: Option<GlobalRefCallback<(AniResponseHeaders,)>>,
}

impl CallBackWebSocketClient {
    pub fn new() -> Self {
        Self {
            on_open: None,
            on_message: None,
            on_close: None,
            on_error: None,
            on_data_end: None,
            on_header_receive: None,
        }
    }
}

pub struct AniClient {
    client: cxx::UniquePtr<ffi::WebSocketClientWrapper>,
    pub callback: CallBackWebSocketClient,
}

impl AniClient {
    pub fn new() -> i64 {
        let client = ffi::CreateWebSocket();
        let callback = CallBackWebSocketClient::new();
        let ws = AniClient { client, callback };
        let client_ptr = ws.client.as_ref().unwrap() as *const _ as usize;
        let web_socket = Box::new(ws);
        let ptr = Box::into_raw(web_socket);
        get_ws_client_map().lock().unwrap().insert(client_ptr, ptr as usize);
        ptr as i64
    }

    pub fn connect(
        &mut self,
        url: &str,
        headers: HashMap<String, String>,
        caPath: Option<String>,
        clientCert: Option<AniClientCert>,
        protocol: Option<String>,
    ) -> Result<(), i32> {
        let options = ffi::AniConnectOptions {
            headers: headers
                .iter()
                .map(|(k, v)| [k.as_str(), v.as_str()])
                .flatten()
                .collect(),
        };
        if let Some(caPath) = caPath {
            ffi::SetCaPath(self.client.pin_mut(), &caPath);
        }
        if let Some(cert) = clientCert {
            ffi::SetClientCert(self.client.pin_mut(), &cert.certPath, &cert.keyPath);
            if let Some(password) = cert.keyPassword {
                ffi::SetCertPassword(self.client.pin_mut(), &password);
            }
        }

        let ret = ffi::Connect(self.client.pin_mut(), url, options);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn send(&mut self, data: Vec<u8>, data_type: i32) -> Result<(), i32> {
        let ret = ffi::Send(self.client.pin_mut(), data, data_type);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn close(&mut self, code: u32, reason: &str) -> Result<(), i32> {
        let options = ffi::AniCloseOption { code, reason };
        let ret = ffi::Close(self.client.pin_mut(), options);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }
    
    pub fn on_open_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterOpenCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn on_message_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterMessageCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn on_close_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterCloseCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn on_error_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterErrorCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn on_data_end_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterDataEndCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn on_header_receive_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterHeaderReceiveCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_open_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterOpenCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_message_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterMessageCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_close_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterCloseCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_error_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterErrorCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_data_end_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterDataEndCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_header_receive_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterHeaderReceiveCallback(self.client.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }
}

impl Drop for AniClient {
    fn drop(&mut self) {
        if let Some(client_ptr) = self.client.as_ref().map(|c| c as *const _ as usize) {
            get_ws_client_map().lock().unwrap().remove(&client_ptr);
        }
    }
}

/**
 * @brief server
 */
static WS_MAP_SERVER: OnceLock<Mutex<HashMap<usize, usize>>> = OnceLock::new();

fn get_ws_server_map() -> &'static Mutex<HashMap<usize, usize>> {
    WS_MAP_SERVER.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn on_error_websocket_server(
    server: Pin<&mut ffi::WebSocketServer>,
    message: String,
    code: u32,
) {
    let server_ptr = &*server as *const _ as *mut ffi::WebSocketServer as usize;
    if let Some(&ws_ptr) = get_ws_server_map().lock().unwrap().get(&server_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniServer) };
        if let Some(cb) = &ws.callback.on_error {
            let error = BusinessError::new(code as i32, message);
            cb.execute(error);
        }
    }
}

pub fn on_connect_websocket_server(server: Pin<&mut ffi::WebSocketServer>, ip: String, port: u32) {
    let server_ptr = &*server as *const _ as *mut ffi::WebSocketServer as usize;
    if let Some(&ws_ptr) = get_ws_server_map().lock().unwrap().get(&server_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniServer) };
        if let Some(cb) = &ws.callback.on_connect {
            let connection = AniWebSocketConnection {
                clientIP: ip,
                clientPort: port as i32,
            };
            cb.execute((connection,));
        }
    }
}

pub fn on_close_websocket_server(
    server: Pin<&mut ffi::WebSocketServer>,
    reason: String,
    code: u32,
    ip: String,
    port: u32,
) {
    let server_ptr = &*server as *const _ as *mut ffi::WebSocketServer as usize;
    if let Some(&ws_ptr) = get_ws_server_map().lock().unwrap().get(&server_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniServer) };
        if let Some(cb) = &ws.callback.on_close {
            let connection = AniWebSocketConnection {
                clientIP: ip,
                clientPort: port as i32,
            };
            let result = AniCloseResult {
                code: code as i32,
                reason: reason,
            };
            cb.execute((connection, result,));
        }
    }
}

pub fn on_message_receive_websocket_server(
    server: Pin<&mut ffi::WebSocketServer>,
    data: String,
    length: u32,
    ip: String,
    port: u32,
) {
    let server_ptr = &*server as *const _ as *mut ffi::WebSocketServer as usize;
    if let Some(&ws_ptr) = get_ws_server_map().lock().unwrap().get(&server_ptr) {
        let ws = unsafe { &mut *(ws_ptr as *mut AniServer) };
        if let Some(cb) = &ws.callback.on_message_receive {
            let data = AniData::S(data);
            let connection = AniWebSocketConnection {
                clientIP: ip,
                clientPort: port as i32,
            };
            let message = AniWebSocketMessage {
                data: data,
                clientConnection: connection,
            };
            cb.execute((message,));
        }
    }
}

pub struct CallBackWebSocketServer {
    pub on_error: Option<GlobalRefErrorCallback>,
    pub on_connect: Option<GlobalRefCallback<(AniWebSocketConnection,)>>,
    pub on_close: Option<GlobalRefCallback<(AniWebSocketConnection, AniCloseResult,)>>,
    pub on_message_receive: Option<GlobalRefCallback<(AniWebSocketMessage,)>>,
}

impl CallBackWebSocketServer {
    pub fn new() -> Self {
        Self {
            on_error: None,
            on_connect: None,
            on_close: None,
            on_message_receive: None,
        }
    }
}

pub struct AniServer {
    server: cxx::UniquePtr<ffi::WebSocketServer>,
    pub callback: CallBackWebSocketServer,
}

impl AniServer {
    pub fn new() -> i64 {
        let server = ffi::CreateWebSocketServer();
        let callback = CallBackWebSocketServer::new();
        let ws = AniServer { server, callback };
        let server_ptr = ws.server.as_ref().unwrap() as *const _ as usize;
        let web_socket_server = Box::new(ws);
        let ptr = Box::into_raw(web_socket_server);
        get_ws_server_map().lock().unwrap().insert(server_ptr, ptr as usize);
        ptr as i64
    }

    pub fn start(
        &mut self,
        serverIP: String,
        serverPort: i32,
        server_cert_path: String,
        server_key_path: String,
        maxConcurrentClientsNumber: i32,
        protocol: String,
        maxConnectionsForOneClient: i32,
    ) -> Result<(), i32> {
        let server_config_cert = ffi::AniServerConfigCert {
            certPath: server_cert_path,
            keyPath: server_key_path,
        };
        let server_config = ffi::AniServerConfig {
            serverIP: serverIP,
            serverPort: serverPort,
            serverCert: server_config_cert,
            maxConcurrentClientsNumber: maxConcurrentClientsNumber,
            protocol: protocol,
            maxConnectionsForOneClient: maxConnectionsForOneClient,
        };
        let ret = ffi::StartServer(self.server.pin_mut(), server_config);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), i32> {
        let ret = ffi::StopServer(self.server.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn send(&mut self, data: Vec<u8>, connection: &AniWebSocketConnection, data_type: i32) -> Result<(), i32> {
        let ret = ffi::SendServerData(self.server.pin_mut(), data, &connection, data_type);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn close(
        &mut self,
        connection: &AniWebSocketConnection,
        code: u32,
        reason: &str,
    ) -> Result<(), i32> {
        let option = ffi::AniCloseOption { code, reason };
        let ret = ffi::CloseServer(self.server.pin_mut(), &connection, option);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn list_all_connections(
        &mut self,
        connections: &mut Vec<AniWebSocketConnection>,
    ) -> Result<(), i32> {
        let ret = ffi::ListAllConnections(self.server.pin_mut(), connections);
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn on_error_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterServerErrorCallback(self.server.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_error_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterServerErrorCallback(self.server.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn on_connect_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterServerConnectCallback(self.server.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_connect_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterServerConnectCallback(self.server.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn on_close_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterServerCloseCallback(self.server.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_close_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterServerCloseCallback(self.server.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn on_message_receive_native(&mut self) -> Result<(), i32> {
        let ret = ffi::RegisterServerMessageReceiveCallback(self.server.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }

    pub fn off_message_receive_native(&mut self) -> Result<(), i32> {
        let ret = ffi::UnregisterServerMessageReceiveCallback(self.server.pin_mut());
        if ret != 0 {
            return Err(ret);
        }
        Ok(())
    }
}

impl Drop for AniServer {
    fn drop(&mut self) {
        if let Some(server_ptr) = self.server.as_ref().map(|c| c as *const _ as usize) {
            get_ws_server_map().lock().unwrap().remove(&server_ptr);
        }
    }
}

#[cxx::bridge(namespace = "OHOS::NetStackAni")]
mod ffi {
    pub struct AniConnectOptions<'a> {
        pub headers: Vec<&'a str>,
    }

    struct AniCloseOption<'a> {
        code: u32,
        reason: &'a str,
    }

    pub struct AniServerConfigCert {
        certPath: String,
        keyPath: String,
    }

    pub struct AniServerConfig {
        serverIP: String,
        serverPort: i32,
        serverCert: AniServerConfigCert,
        maxConcurrentClientsNumber: i32,
        protocol: String,
        maxConnectionsForOneClient: i32,
    }

    extern "Rust" {
        type AniClient;
        fn on_open_websocket_client(client: Pin<&mut WebSocketClientWrapper>, message: String, status: u32);
        fn on_message_websocket_client(client: Pin<&mut WebSocketClientWrapper>, data: String, len: u32);
        fn on_close_websocket_client(client: Pin<&mut WebSocketClientWrapper>, reason: String, code: u32);
        fn on_error_websocket_client(client: Pin<&mut WebSocketClientWrapper>, errMessage: String, errCode: u32);
        fn on_data_end_websocket_client(client: Pin<&mut WebSocketClientWrapper>);
        fn on_header_receive_websocket_client(client: Pin<&mut WebSocketClientWrapper>, keys: &mut Vec<String>, values: &mut Vec<String>);
        fn header_push_data(header: &mut Vec<String>, data: String);

        type AniServer;
        type AniWebSocketConnection;
        fn get_web_socket_connection_client_ip(conn: &AniWebSocketConnection) -> String;
        fn get_web_socket_connection_client_port(conn: &AniWebSocketConnection) -> i32;
        fn socket_connection_push_data(
            connection_info_value: &mut Vec<AniWebSocketConnection>,
            clientIP: String,
            clientPort: i32,
        );

        fn on_error_websocket_server(server: Pin<&mut WebSocketServer>, message: String, code: u32);
        fn on_connect_websocket_server(server: Pin<&mut WebSocketServer>, ip: String, port: u32);
        fn on_close_websocket_server(
            server: Pin<&mut WebSocketServer>,
            reason: String,
            code: u32,
            ip: String,
            port: u32,
        );
        fn on_message_receive_websocket_server(
            server: Pin<&mut WebSocketServer>,
            data: String,
            length: u32,
            ip: String,
            port: u32,
        );
    }

    unsafe extern "C++" {
        include!("websocket_ani.h");

        type WebSocketClientWrapper;

        fn CreateWebSocket() -> UniquePtr<WebSocketClientWrapper>;

        fn Connect(client: Pin<&mut WebSocketClientWrapper>, url: &str, options: AniConnectOptions)
            -> i32;

        fn SetCaPath(client: Pin<&mut WebSocketClientWrapper>, caPath: &str);

        fn SetClientCert(client: Pin<&mut WebSocketClientWrapper>, certPath: &str, key: &str);

        fn SetCertPassword(client: Pin<&mut WebSocketClientWrapper>, password: &str);

        fn Send(client: Pin<&mut WebSocketClientWrapper>, data: Vec<u8>, data_type: i32) -> i32;

        fn Close(client: Pin<&mut WebSocketClientWrapper>, options: AniCloseOption) -> i32;

        fn RegisterOpenCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn RegisterMessageCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn RegisterCloseCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn RegisterErrorCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn RegisterDataEndCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn RegisterHeaderReceiveCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn UnregisterOpenCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn UnregisterMessageCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn UnregisterCloseCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn UnregisterErrorCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn UnregisterDataEndCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        fn UnregisterHeaderReceiveCallback(client: Pin<&mut WebSocketClientWrapper>) -> i32;

        #[namespace = "OHOS::NetStack::WebSocketServer"]
        type WebSocketServer;

        fn CreateWebSocketServer() -> UniquePtr<WebSocketServer>;

        fn StartServer(server: Pin<&mut WebSocketServer>, options: AniServerConfig) -> i32;

        fn StopServer(server: Pin<&mut WebSocketServer>) -> i32;

        fn SendServerData(
            server: Pin<&mut WebSocketServer>,
            data: Vec<u8>,
            connection: &AniWebSocketConnection,
            data_type: i32,
        ) -> i32;

        fn CloseServer(
            server: Pin<&mut WebSocketServer>,
            connection: &AniWebSocketConnection,
            options: AniCloseOption,
        ) -> i32;

        fn ListAllConnections(
            server: Pin<&mut WebSocketServer>,
            connections: &mut Vec<AniWebSocketConnection>,
        ) -> i32;

        fn RegisterServerErrorCallback(server: Pin<&mut WebSocketServer>) -> i32;

        fn RegisterServerConnectCallback(server: Pin<&mut WebSocketServer>) -> i32;

        fn RegisterServerCloseCallback(server: Pin<&mut WebSocketServer>) -> i32;

        fn RegisterServerMessageReceiveCallback(server: Pin<&mut WebSocketServer>) -> i32;

        fn UnregisterServerErrorCallback(server: Pin<&mut WebSocketServer>) -> i32;

        fn UnregisterServerConnectCallback(server: Pin<&mut WebSocketServer>) -> i32;

        fn UnregisterServerCloseCallback(server: Pin<&mut WebSocketServer>) -> i32;

        fn UnregisterServerMessageReceiveCallback(server: Pin<&mut WebSocketServer>) -> i32;
    }
}
