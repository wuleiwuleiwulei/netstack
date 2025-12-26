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
use std::{collections::HashMap, ffi::CStr};
use ani_rs::{
    business_error::BusinessError,
    objects::{AniFnObject, AniAsyncCallback, AniErrorCallback, AniRef},
    AniEnv,
};
use serde::{Deserialize, Serialize};

use crate::{
    bridge::{self, convert_to_business_error, AniCleaner},
    wrapper::AniClient,
};

#[ani_rs::native]
pub(crate) fn web_socket_clean(this: AniCleaner) -> Result<(), BusinessError> {
    let _ = unsafe { Box::from_raw(this.nativePtr as *mut AniClient) };
    Ok(())
}

#[ani_rs::native]
pub fn create_web_socket<'local>(env: &AniEnv<'local>) -> Result<AniRef<'local>, BusinessError> {
    info!("Creating WebSocket instance");
    static WEB_SOCKET_CLASS: &CStr = unsafe {
        CStr::from_bytes_with_nul_unchecked(b"@ohos.net.webSocket.webSocket.WebSocketInner\0")
    };
    static CTOR_SIGNATURE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"l:\0") };
    let ptr = AniClient::new();
    let class = env.find_class(WEB_SOCKET_CLASS).unwrap();
    let obj = env
        .new_object_with_signature(&class, CTOR_SIGNATURE, (ptr,))
        .unwrap();
    Ok(obj.into())
}

#[ani_rs::native]
pub(crate) fn connect_sync(
    this: bridge::AniWebSocket,
    url: String,
    options: Option<bridge::AniWebSocketRequestOptions>,
) -> Result<bool, BusinessError> {
    info!("Connecting to WebSocket at URL: {}", url);

    let web_socket = unsafe { &mut *(this.nativePtr as *mut AniClient) };
    let mut headers = HashMap::new();
    let (mut caPath, mut clientCert, mut protocol) = (None, None, None);

    if let Some(options) = options {
        if let Some(header) = options.header {
            headers = header;
        }
        if let Some(path) = options.caPath {
            caPath = Some(path);
        }
        if let Some(cert) = options.clientCert {
            clientCert = Some(cert);
        }
        if let Some(p) = options.protocol {
            protocol = Some(p);
        }
    }
    web_socket
        .connect(&url, headers, caPath, clientCert, protocol)
        .map(|_| true)
        .map_err(|e| convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn send_sync(
    this: bridge::AniWebSocket,
    data: bridge::AniData,
) -> Result<bool, BusinessError> {
    let web_socket = unsafe { &mut *(this.nativePtr as *mut AniClient) };
    let (s, data_type) = match data {
        bridge::AniData::S(s) => (s.into_bytes(), 0),
        bridge::AniData::ArrayBuffer(arr) => (arr.to_vec(), 1),
    };
    web_socket
        .send(s, data_type)
        .map(|_| true)
        .map_err(|e| convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn close_sync(
    this: bridge::AniWebSocket,
    options: Option<bridge::AniWebSocketCloseOptions>,
) -> Result<bool, BusinessError> {
    let web_socket = unsafe { &mut *(this.nativePtr as *mut AniClient) };

    let code = options.as_ref().and_then(|opt| opt.code).unwrap_or(0) as u32;
    let reason = options
        .as_ref()
        .and_then(|opt| opt.reason.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("");

    web_socket
        .close(code as u32, &reason)
        .map(|_| true)
        .map_err(|e| convert_to_business_error(e))
}

#[ani_rs::native]
pub(crate) fn on_open(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_open = Some(callback.into_global_callback(env).unwrap());
    web_socket.on_open_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_open(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_open = None;
    web_socket.off_open_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_message(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_message = Some(async_callback.into_global_callback(env).unwrap());
    web_socket.on_message_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_message(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_message = None;
    web_socket.off_message_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_close(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_close = Some(async_callback.into_global_callback(env).unwrap());
    web_socket.on_close_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_close(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_close = None;
    web_socket.off_close_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_error(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    error_callback: AniErrorCallback,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_error = Some(error_callback.into_global_callback(env).unwrap());
    web_socket.on_error_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_error(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    error_callback: AniErrorCallback,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_error = None;
    web_socket.off_error_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_data_end(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_data_end = Some(callback.into_global_callback(env).unwrap());
    web_socket.on_data_end_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_end(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_data_end = None;
    web_socket.off_data_end_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_header_receive(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_header_receive = Some(callback.into_global_callback(env).unwrap());
    web_socket.on_header_receive_native();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_header_receive(
    env: &AniEnv,
    this: bridge::AniWebSocket,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let web_socket = unsafe { &mut (*(this.nativePtr as *mut AniClient)) };
    web_socket.callback.on_header_receive = None;
    web_socket.off_header_receive_native();
    Ok(())
}