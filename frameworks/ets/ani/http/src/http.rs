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

use std::{
    ffi::CStr,
    sync::atomic::{AtomicBool, Ordering},
};

use ani_rs::{
    business_error::BusinessError,
    typed_array::ArrayBuffer,
    objects::{AniAsyncCallback, AniFnObject, AniRef, AniObject, JsonValue},
    AniEnv, signature
};
use netstack_rs::{
    error::HttpErrorCode,
    request::{
        Request,
        EscapedData,
        run_cache,
        flush_cache,
        delete_cache
    },
    task::RequestTask
};

use crate::{
    bridge::{
        convert_to_business_error, Cleaner, HttpRequest, HttpRequestOptions, HttpResponseCache, TlsConfig, HttpProxy, CertificatePinning
    },
    callback::TaskCallback,
};

pub struct Task {
    pub request_task: Option<RequestTask>,
    pub callback: Option<TaskCallback>,
    pub is_destroy: AtomicBool,
}

impl Task {
    pub fn new() -> Self {
        Self {
            request_task: None,
            callback: None,
            is_destroy: AtomicBool::new(false),
        }
    }
}

#[ani_rs::native]
pub fn create_http_ptr() -> Result<i64, BusinessError> {
    let request = Box::new(Task::new());
    let ptr = Box::into_raw(request);
    Ok(ptr as i64)
}

pub fn parse_escaped_data_from_original_data<'local>(env: &AniEnv, obj_data: AniObject<'local>) -> EscapedData {
    let string_class = env.find_class(signature::STRING).unwrap();
    let array_buffer_class = env.find_class(signature::ARRAY_BUFFER).unwrap();
    let mut res = EscapedData {
        data_type: 0,
        data: String::new(),
    };
    if env.instance_of(&obj_data, &string_class).unwrap() {
        res.data_type = 0;
        res.data = env.deserialize::<String>(obj_data).unwrap();
    } else if env.instance_of(&obj_data, &array_buffer_class).unwrap() {
        res.data_type = 2;
        let buffer = env.deserialize::<ArrayBuffer>(obj_data).unwrap();
        res.data = String::from_utf8_lossy(buffer.as_ref()).to_string();
    } else {
        let json_value = env.deserialize::<JsonValue>(obj_data).unwrap();
        res.data_type = 1;
        res.data = json_value.stringify(env).unwrap();
    };
    res
}

pub fn http_set_options(
    env: &AniEnv,
    request: &mut Request<TaskCallback>,
    options: HttpRequestOptions) {
    if let Some(method) = options.method {
        request.method(method.to_str());
    }
    if let Some(priority) = options.priority {
        request.priority(priority as u32);
    }
    if let Some(read_timeout) = options.read_timeout {
        request.timeout(read_timeout as u32);
    }
    if let Some(connect_timeout) = options.connect_timeout {
        request.connect_timeout(connect_timeout as u32);
    }
    if let Some(headers) = options.header {
        request.header_ext(parse_escaped_data_from_original_data(env, headers));
    }
    if let Some(protocol) = options.using_protocol {
        request.protocol(protocol.to_i32());
    }
    if let Some(using_proxy) = options.using_proxy {
        let obj_data = using_proxy;
        let bool_class = env.find_class(signature::BOOLEAN).unwrap();
        if env.instance_of(&obj_data, &bool_class).unwrap() {
            let opt = env.deserialize::<bool>(obj_data).unwrap();
            let using_type = if opt {
                netstack_rs::request::HttpProxyType::PROXY_TYPE_MAX
            } else {
                netstack_rs::request::HttpProxyType::NOT_USE
            };
            request.using_proxy_type(using_type.to_i32());
        } else {
            let opt = env.deserialize::<HttpProxy>(obj_data).unwrap();
            let mut exclusions = String::new();
            for item in opt.exclusion_list {
                exclusions.push_str(&item);
            }
            let mut http_proxy = netstack_rs::request::HttpProxy {
                host: opt.host,
                port: opt.port,
                exclusions: exclusions,
            };
            request.using_proxy_type(netstack_rs::request::HttpProxyType::USE_SPECIFIED.to_i32());
            request.specified_proxy(http_proxy);
        }
    }
    if let Some(&max_limit) = options.max_limit.as_ref() {
        request.max_limit(max_limit as u32);
    }
    if let Some(ca_path) = options.ca_path {
        request.ca_path(&ca_path);
    }
    if let Some(resume_from) = options.resume_from {
        request.resume_from(resume_from);
    }
    if let Some(resume_to) = options.resume_to {
        request.resume_to(resume_to);
    }
    if let Some(address_family) = options.address_family {
        request.address_family(address_family.to_i32());
    }
    if let Some(extra_data) = options.extra_data {
        request.extra_data(parse_escaped_data_from_original_data(env, extra_data));
    }
    if let Some(expect_data_type) = options.expect_data_type {
        request.expect_data_type(expect_data_type.to_i32());
    }
    if let Some(using_cache) = options.using_cache {
        request.using_cache(using_cache);
    }
    if let Some(client_cert) = options.client_cert {
        request.client_cert(client_cert.into());
    }
    if let Some(dns_over_https) = options.dns_over_https {
        request.dns_over_https(&dns_over_https);
    }
    if let Some(dns_servers) = options.dns_servers {
        request.dns_servers(dns_servers);
    }
    if let Some(multi_form_data_list) = options.multi_form_data_list {
        for item in multi_form_data_list {
            let mut escaped_data: Option<String> = None;
            if let Some(original_data) = item.data {
                escaped_data = Some(parse_escaped_data_from_original_data(env, original_data).data);
            }
            let mut multi_form_data = netstack_rs::request::MultiFormData {
                name: item.name,
                content_type: item.content_type,
                remote_file_name: item.remote_file_name.unwrap_or(String::new()),
                data: escaped_data.unwrap_or(String::new()),
                file_path: item.file_path.unwrap_or(String::new()),
            };
            request.add_multi_form_data(multi_form_data);
        }
    }
    if let Some(remote_validation) = options.remote_validation {
        request.remote_validation(&remote_validation);
    }
    if let Some(tls_options) = options.tls_options {
        let obj_data = tls_options;
        let string_class = env.find_class(signature::STRING).unwrap();
        if env.instance_of(&obj_data, &string_class).unwrap() {
            // noting todo
        } else {
            let opt = env.deserialize::<TlsConfig>(obj_data).unwrap();
            request.tls_options(opt.into());
        }
    }
    if let Some(server_authentication) = options.server_authentication {
        request.server_authentication(server_authentication.into());
    }
    if let Some(certificate_pinning) = options.certificate_pinning {
        let obj_data = certificate_pinning;
        let array_class = env.find_class(signature::ARRAY).unwrap();
        let mut pinRes = String::new();
        if env.instance_of(&obj_data, &array_class).unwrap() {
            let opt = env.deserialize::<Vec<CertificatePinning>>(obj_data).unwrap();
            for item in opt {
                if (item.hash_algorithm == "SHA-256") {
                    pinRes.push_str(&format!("sha256//{};", item.public_key_hash));
                }
            }
        } else {
            let opt = env.deserialize::<CertificatePinning>(obj_data).unwrap();
            if (opt.hash_algorithm == "SHA-256") {
                pinRes.push_str(&format!("sha256//{};", opt.public_key_hash));
            }
        }
        if !pinRes.is_empty() {
            pinRes.pop();
            request.certificate_pinning(&pinRes);
        }
        let mut bytes = pinRes.into_bytes();
        for byte in &mut bytes {
            *byte = 0;
        }
    }
}

#[ani_rs::native]
pub fn create_http_response_cache<'local>(
    env: &AniEnv<'local>, cacheSize : Option<i32>) -> Result<AniRef<'local>, BusinessError> {
    static HTTP_RESPONSE_CACHE_CLASS: &CStr =
        unsafe { CStr::from_bytes_with_nul_unchecked(b"@ohos.net.http.http.HttpResponseCacheInner\0") };
    static CTOR_SIGNATURE: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"l:\0") };

    let class = env.find_class(HTTP_RESPONSE_CACHE_CLASS).unwrap();
    let obj = env
        .new_object_with_signature(&class, CTOR_SIGNATURE, (0,))
        .unwrap();
    run_cache(cacheSize);
    Ok(obj.into())
}

#[ani_rs::native]
pub(crate) fn request(
    env: &AniEnv,
    this: HttpRequest,
    url: String,
    async_callback: AniAsyncCallback,
    options: Option<HttpRequestOptions>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    if task.is_destroy.load(Ordering::Relaxed) {
        error!("Request is already destroyed");
        let business_error = BusinessError::new(
            HttpErrorCode::HttpUnknownOtherError as i32,
            "Request is already destroyed".to_string(),
        );
        let undefined: Option<bool> = None; //None will serialize arkts's undefined
        async_callback
            .execute_local(env, Some(business_error), (undefined,))
            .unwrap();
        return Ok(());
    }
    let mut request = Request::<TaskCallback>::new();

    request.url(url.as_str());
    if let Some(opts) = options {
        http_set_options(env, &mut request, opts);
    }

    let mut cb = task.callback.take().unwrap_or_else(TaskCallback::new);
    cb.on_response = Some(async_callback.clone().into_global_callback(env).unwrap());
    request.callback(cb);
    let mut request_task = request.build();
    if !request_task.start() {
        let error = request_task.get_error();
        error!("request_task.start error = {:?}", error);
        let business_error = convert_to_business_error(&error);
        let undefined: Option<bool> = None; //None will serialize arkts's undefined
        async_callback
            .execute_local(env, Some(business_error), (undefined,))
            .unwrap();
        return Ok(());
    }
    task.request_task = Some(request_task);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn request_in_stream(
    env: &AniEnv,
    this: HttpRequest,
    url: String,
    async_callback: AniAsyncCallback,
    options: Option<HttpRequestOptions>,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    if task.is_destroy.load(Ordering::Relaxed) {
        error!("Request is already destroyed");
        let business_error = BusinessError::new(
            HttpErrorCode::HttpUnknownOtherError as i32,
            "Request is already destroyed".to_string(),
        );
        let undefined: Option<bool> = None; //None will serialize arkts's undefined
        async_callback
            .execute_local(env, Some(business_error), (undefined,))
            .unwrap();
        return Ok(());
    }
    let mut request = Request::<TaskCallback>::new();

    request.url(url.as_str());
    if let Some(opts) = options {
        http_set_options(env, &mut request, opts);
    }

    let mut cb = task.callback.take().unwrap_or_else(TaskCallback::new);
    cb.on_response_in_stream = Some(async_callback.clone().into_global_callback(env).unwrap());
    request.callback(cb);
    let mut request_task = request.build();
    request_task.set_is_request_in_stream(true);
    if !request_task.start() {
        let error = request_task.get_error();
        error!("request_task.start error = {:?}", error);
        let business_error = convert_to_business_error(&error);
        let undefined: Option<bool> = None; //None will serialize arkts's undefined
        async_callback
            .execute_local(env, Some(business_error), (undefined,))
            .unwrap();
        return Ok(());
    }
    task.request_task = Some(request_task);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn destroy(this: HttpRequest) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    if let Some(request_task) = task.request_task.take() {
        request_task.cancel();
    }
    task.is_destroy.store(true, Ordering::Relaxed);
    Ok(())
}

#[ani_rs::native]
pub(crate) fn clean_http_request(this: Cleaner) -> Result<(), BusinessError> {
    unsafe {
        let _ = Box::from_raw(this.native_ptr as *mut Task);
    };
    Ok(())
}

#[ani_rs::native]
pub(crate) fn clean_http_cache(this: Cleaner) -> Result<(), BusinessError> {
    Ok(())
}

pub(crate) fn on_header_receive(
    env: &AniEnv,
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut callback) => {
            // Convert the async callback to a global reference
            callback.on_header_receive = Some(async_callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut task_callback = TaskCallback::new();
            task_callback.on_header_receive =
                Some(async_callback.into_global_callback(env).unwrap());
            task.callback = Some(task_callback);
        }
    }
    Ok(())
}

pub(crate) fn off_header_receive(
    this: HttpRequest,
    async_callback: AniAsyncCallback,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_header_receive();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut callback) => {
            callback.on_header_receive = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_headers_receive(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_headers_receive = Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_headers_receive =
                Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_headers_receive(
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_headers_receive();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_headers_receive = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_data_receive(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_data_receive = Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_data_receive = Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_receive(
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_data_receive();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_data_receive = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_data_end(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_data_end = Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_data_end = Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_end(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_data_end = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_data_receive_progress(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_data_receive_progress =
                Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_data_receive_progress =
                Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_receive_progress(
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_progress();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_data_receive_progress = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn on_data_send_progress(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_data_send_progress =
                Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_data_send_progress =
                Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn off_data_send_progress(
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.off_progress();
        }
        None => {
            // noting todo
        }
    }
    match task.callback {
        Some(ref mut task_callback) => {
            task_callback.on_data_send_progress = None;
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn once_headers_receive(
    env: &AniEnv,
    this: HttpRequest,
    callback: AniFnObject,
) -> Result<(), BusinessError> {
    let task = unsafe { &mut (*(this.native_ptr as *mut Task)) };
    match task.callback {
        Some(ref mut task_callback) => {
            // Convert the async callback to a global reference
            task_callback.on_headers_receive = Some(callback.into_global_callback(env).unwrap());
        }
        None => {
            let mut new_task_callback = TaskCallback::new();
            new_task_callback.on_headers_receive =
                Some(callback.into_global_callback(env).unwrap());
            task.callback = Some(new_task_callback);
        }
    }
    match task.request_task {
        Some(ref mut request_task) => {
            request_task.set_is_headers_once(true);
        }
        None => {
            // noting todo
        }
    }
    Ok(())
}

#[ani_rs::native]
pub(crate) fn flush(this: HttpResponseCache) -> Result<(), BusinessError> {
    flush_cache();
    Ok(())
}

#[ani_rs::native]
pub(crate) fn delete(this: HttpResponseCache) -> Result<(), BusinessError> {
    delete_cache();
    Ok(())
}
