// Copyright (C) 2024 Huawei Device Co., Ltd.
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

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::collections::HashMap;

use cxx::{let_cxx_string, SharedPtr};
use ffi::{HttpClientRequest, HttpClientTask, NewHttpClientTask, OnCallback};
use netstack_common::debug;

use crate::error::{HttpClientError, HttpErrorCode};
use crate::request::{RequestCallback, CertType, ClientCert, MultiFormData, ServerAuthentication, TlsConfig, TlsVersion, EscapedData, HttpProxy};
use crate::response::{Response, ResponseCode, HttpDataType};
use crate::task::{RequestTask, TaskStatus};

pub struct CallbackWrapper {
    inner: Option<Box<dyn RequestCallback>>,
    reset: Arc<AtomicBool>,
    task: Weak<Mutex<SharedPtr<HttpClientTask>>>,
    current: u64,
}

impl CallbackWrapper {
    pub(crate) fn from_callback(
        inner: Box<dyn RequestCallback + 'static>,
        reset: Arc<AtomicBool>,
        task: Weak<Mutex<SharedPtr<HttpClientTask>>>,
        current: u64,
    ) -> Self {
        Self {
            inner: Some(inner),
            reset,
            task,
            current,
        }
    }
}

impl CallbackWrapper {
    fn on_success(
        &mut self,
        _request: &HttpClientRequest,
        response: &ffi::HttpClientResponse,
        is_request_in_stream: bool) {
        debug!("on_success callback is called");
        let Some(mut callback) = self.inner.take() else {
            return;
        };
        let response = Response::from_ffi(response);
        callback.on_success(response, is_request_in_stream);
    }

    fn on_fail(
        &mut self,
        _request: &HttpClientRequest,
        response: &ffi::HttpClientResponse,
        error: &ffi::HttpClientError,
        is_request_in_stream: bool
    ) {
        debug!("on_fail callback is called");
        let Some(mut callback) = self.inner.take() else {
            return;
        };
        let client_error = HttpClientError::from_ffi(error);
        let response = Response::from_ffi(response);
        callback.on_fail(response, client_error, is_request_in_stream);
    }

    fn on_cancel(
        &mut self,
        request: &HttpClientRequest,
        response: &ffi::HttpClientResponse,
        is_request_in_stream: bool
    ) {
        debug!("on_cancel callback is called");
        let Some(mut callback) = self.inner.take() else {
            return;
        };

        if self.reset.load(Ordering::SeqCst) {
            let (new_task, new_callback) = self.create_new_task(callback, request, response);
            Self::start_new_task(new_task, new_callback);
            self.reset.store(false, Ordering::SeqCst);
        } else {
            let response = Response::from_ffi(response);
            callback.on_cancel(response, is_request_in_stream);
        }
    }

    fn on_data_receive(
        &mut self,
        task: SharedPtr<ffi::HttpClientTask>,
        data: *const u8,
        size: usize,
    ) {
        let Some(callback) = self.inner.as_mut() else {
            return;
        };
        self.current += size as u64;
        let data = unsafe { std::slice::from_raw_parts(data, size) };
        let task = RequestTask::from_ffi(task);
        callback.on_data_receive(data, task);
    }

    fn on_progress(&mut self, dl_total: u64, dl_now: u64, ul_total: u64, ul_now: u64) {
        let Some(callback) = self.inner.as_mut() else {
            return;
        };
        callback.on_progress(dl_total, dl_now, ul_total, ul_now);
    }

    fn on_header_receive(
        &mut self,
        header: String,
    ) {
        let Some(callback) = self.inner.as_mut() else {
            return;
        };
        callback.on_header_receive(header);
    }

    fn on_headers_receive(
        &mut self,
        headers_conversion: Vec<String>,
    ) {
        let Some(callback) = self.inner.as_mut() else {
            return;
        };
        let mut ret = HashMap::new();
        let mut headers_iter = headers_conversion.into_iter();
        loop {
            if let Some(key) = headers_iter.next() {
                if let Some(value) = headers_iter.next() {
                    ret.insert(key.to_lowercase(), value);
                    continue;
                }
            }
            break;
        }
        callback.on_headers_receive(ret);
    }

    fn create_new_task(
        &mut self,
        mut callback: Box<dyn RequestCallback>,
        request: &HttpClientRequest,
        response: &ffi::HttpClientResponse,
    ) -> (SharedPtr<HttpClientTask>, Box<CallbackWrapper>) {
        if self.current > 0 && !set_range(request, response, &mut self.current) {
            callback.on_restart();
        }

        let new_task = NewHttpClientTask(request);
        let new_callback = Box::new(CallbackWrapper::from_callback(
            callback,
            self.reset.clone(),
            self.task.clone(),
            self.current,
        ));
        (new_task, new_callback)
    }

    fn start_new_task(task: SharedPtr<HttpClientTask>, callback: Box<CallbackWrapper>) {
        if let Some(r) = callback.task.upgrade() {
            *r.lock().unwrap() = task.clone();
        }
        OnCallback(&task, callback);
        RequestTask::pin_mut(&task).Start();
    }
}

fn set_range(
    request: &HttpClientRequest,
    response: &ffi::HttpClientResponse,
    current: &mut u64,
) -> bool {
    let response = Response::from_ffi(response);
    let headers = response.headers();
    let ptr = request as *const HttpClientRequest as *mut HttpClientRequest;
    let mut support_range = false;

    if let Some(etag) = headers.get("etag") {
        let_cxx_string!(key = "If-Range");
        let_cxx_string!(val = etag);
        unsafe {
            Pin::new_unchecked(ptr.as_mut().unwrap()).SetHeader(&key, &val);
        }
        support_range = true;
    } else if let Some(last_modified) = headers.get("last-modified") {
        let_cxx_string!(key = "If-Range");
        let_cxx_string!(val = last_modified);
        unsafe {
            Pin::new_unchecked(ptr.as_mut().unwrap()).SetHeader(&key, &val);
        }
        support_range = true;
    }

    if support_range {
        let_cxx_string!(key = "Range");
        let bytes = format!("bytes={}-", current);
        let_cxx_string!(val = bytes);
        unsafe {
            Pin::new_unchecked(ptr.as_mut().unwrap()).SetHeader(&key, &val);
        }
    } else {
        *current = 0;
    }
    support_range
}

unsafe impl Send for HttpClientTask {}
unsafe impl Sync for HttpClientTask {}

impl From<crate::request::ClientCert> for ffi::ClientCert {
    fn from(client_cert: ClientCert) -> Self {
        let cert_type = match client_cert.cert_type {
            Some(ct) => match ct {
                CertType::Pem => ffi::CertType::Pem,
                CertType::Der => ffi::CertType::Der,
                CertType::P12 => ffi::CertType::P12,
            },
            None => ffi::CertType::Pem
        };
        
        let key_password = match client_cert.key_password {
            Some(kp) => kp,
            None => "".to_string()
        };

        ffi::ClientCert {
            cert_path: client_cert.cert_path,
            cert_type,
            key_path: client_cert.key_path,
            key_password,
        }
    }
}

impl From<crate::request::EscapedData> for ffi::EscapedDataRust {
    fn from(value: EscapedData) -> Self {
        let escaped_type = match value.data_type {
            0 => ffi::HttpDataType::STRING,
            1 => ffi::HttpDataType::OBJECT,
            2 => ffi::HttpDataType::ARRAY_BUFFER,
            _ => ffi::HttpDataType::NO_DATA_TYPE,
        };
        ffi::EscapedDataRust {
            data_type: escaped_type,
            data: value.data,
        }
    }
}

impl From<crate::request::MultiFormData> for ffi::MultiFormDataRust {
    fn from(multi_form_data: MultiFormData) -> Self {
        ffi::MultiFormDataRust {
            name: multi_form_data.name,
            content_type: multi_form_data.content_type,
            remote_file_name: multi_form_data.remote_file_name,
            data: multi_form_data.data,
            file_path: multi_form_data.file_path,
        }
    }
}

impl From<crate::request::ServerAuthentication> for ffi::ServerAuthentication {
    fn from(server_auth: ServerAuthentication) -> Self {
        let auth_type = match server_auth.authentication_type {
            Some(ty) => ty,
            None => "".to_string()
        };
        
        ffi::ServerAuthentication {
            username: server_auth.credential.username,
            password: server_auth.credential.password,
            authentication_type: auth_type,
        }
    }
}

impl From<crate::request::TlsConfig> for ffi::TlsConfigRust {
    fn from(tls_config: TlsConfig) -> Self {
        let min = match tls_config.tls_version_min {
            TlsVersion::TlsV_1_0 => ffi::TlsVersionRust::TlsV_1_0,
            TlsVersion::TlsV_1_1 => ffi::TlsVersionRust::TlsV_1_1,
            TlsVersion::TlsV_1_2 => ffi::TlsVersionRust::TlsV_1_2,
            TlsVersion::TlsV_1_3 => ffi::TlsVersionRust::TlsV_1_3
        };
        let max = match tls_config.tls_version_max {
            TlsVersion::TlsV_1_0 => ffi::TlsVersionRust::TlsV_1_0,
            TlsVersion::TlsV_1_1 => ffi::TlsVersionRust::TlsV_1_1,
            TlsVersion::TlsV_1_2 => ffi::TlsVersionRust::TlsV_1_2,
            TlsVersion::TlsV_1_3 => ffi::TlsVersionRust::TlsV_1_3
        };
        ffi::TlsConfigRust {
            tls_version_min: min,
            tls_version_max: max,
            cipher_suites: tls_config.cipher_suites.unwrap_or_default(),
        }
    }
}

impl From<crate::request::HttpProxy> for ffi::HttpProxyRust {
    fn from(http_ptoxy: HttpProxy) -> Self {
        ffi::HttpProxyRust {
            host: http_ptoxy.host,
            port: http_ptoxy.port,
            exclusions: http_ptoxy.exclusions,
        }
    }
}

#[allow(unused_unsafe)]
#[cxx::bridge(namespace = "OHOS::Request")]
pub(crate) mod ffi {

    enum CertType {
        Pem,
        Der,
        P12,
    }

    struct EscapedDataRust {
        data_type: HttpDataType,
        data: String,
    }

    struct ClientCert {
        cert_path: String,
        cert_type: CertType,
        key_path: String,
        key_password: String,
    }

    struct MultiFormDataRust {
        name: String,
        content_type: String,
        remote_file_name: String,
        data: String,
        file_path: String,
    }

    struct ServerAuthentication {
        username : String,
        password: String,
        authentication_type: String,
    }

    enum TlsVersionRust {
        DEFAULT = 0,
        TlsV_1_0 = 4,
        TlsV_1_1 = 5,
        TlsV_1_2 = 6,
        TlsV_1_3 = 7,
    }

    struct TlsConfigRust {
        pub tls_version_min: TlsVersionRust,
        pub tls_version_max: TlsVersionRust,
        pub cipher_suites: Vec<String>,
    }

    struct HttpProxyRust {
        pub host: String,

        pub port: i32,

        pub exclusions: String,
    }
    extern "Rust" {
        type CallbackWrapper;
        fn on_success(
            self: &mut CallbackWrapper,
            request: &HttpClientRequest,
            response: &HttpClientResponse,
            is_request_in_stream: bool
        );
        fn on_fail(
            self: &mut CallbackWrapper,
            request: &HttpClientRequest,
            response: &HttpClientResponse,
            error: &HttpClientError,
            is_request_in_stream: bool
        );
        fn on_cancel(
            self: &mut CallbackWrapper,
            request: &HttpClientRequest,
            response: &HttpClientResponse,
            is_request_in_stream: bool
        );
        unsafe fn on_data_receive(
            self: &mut CallbackWrapper,
            task: SharedPtr<HttpClientTask>,
            data: *const u8,
            size: usize,
        );
        fn on_progress(
            self: &mut CallbackWrapper,
            dl_total: u64,
            dl_now: u64,
            ul_total: u64,
            ul_now: u64,
        );
        unsafe fn on_headers_receive(
            self: &mut CallbackWrapper,
            headers: Vec<String>,
        );
        unsafe fn on_header_receive(
            self: &mut CallbackWrapper,
            header: String,
        );
    }

    unsafe extern "C++" {
        include!("http_client_request.h");
        include!("wrapper.h");
        include!("http_client_task.h");
        include!("netstack_common_utils.h");
        include!("cache_proxy_ani.h");

        fn RunCache();
        fn RunCacheWithSize(capacity: usize);

        fn FlushCache();
        fn StopCacheAndDelete();

        #[namespace = "OHOS::NetStack::HttpClient"]
        type TaskStatus;

        #[namespace = "OHOS::NetStack::HttpClient"]
        type ResponseCode;

        #[namespace = "OHOS::NetStack::HttpClient"]
        type HttpClientRequest;

        #[namespace = "OHOS::NetStack::HttpClient"]
        type HttpErrorCode;

        #[namespace = "OHOS::NetStack::HttpClient"]
        type HttpDataType;

        fn NewHttpClientRequest() -> UniquePtr<HttpClientRequest>;
        fn SetURL(self: Pin<&mut HttpClientRequest>, url: &CxxString);
        fn SetMethod(self: Pin<&mut HttpClientRequest>, method: &CxxString);
        fn SetHeader(self: Pin<&mut HttpClientRequest>, key: &CxxString, val: &CxxString);
        fn SetTimeout(self: Pin<&mut HttpClientRequest>, timeout: u32);
        fn SetPriority(self: Pin<&mut HttpClientRequest>, priority: u32);
        fn SetConnectTimeout(self: Pin<&mut HttpClientRequest>, timeout: u32);
        unsafe fn SetBody(request: Pin<&mut HttpClientRequest>, data: *const u8, length: usize);
        fn SetHttpProtocol(request: Pin<&mut HttpClientRequest>, protocol: i32);
        fn SetUsingHttpProxyType(request: Pin<&mut HttpClientRequest>, proxy_type: i32);
        fn SetSpecifiedHttpProxy(request: Pin<&mut HttpClientRequest>, proxy: &HttpProxyRust);
        fn SetMaxLimit(self: Pin<&mut HttpClientRequest>, max_limit: u32);
        fn SetCaPath(self: Pin<&mut HttpClientRequest>, path: &CxxString);
        fn SetResumeFrom(self: Pin<&mut HttpClientRequest>, resume_from: i64);
        fn SetResumeTo(self: Pin<&mut HttpClientRequest>, resume_from: i64);
        fn SetAddressFamily(request: Pin<&mut HttpClientRequest>, address_family: i32);
        fn SetExtraData(request: Pin<&mut HttpClientRequest>, extra_data: &EscapedDataRust);
        fn SetExpectDataType(request: Pin<&mut HttpClientRequest>, expect_data_type: i32);
        fn SetUsingCache(self: Pin<&mut HttpClientRequest>, using_cache: bool);
        fn SetClientCert(request: Pin<&mut HttpClientRequest>, client_cert: &ClientCert);
        fn SetDNSOverHttps(self: Pin<&mut HttpClientRequest>, dns_over_https: &CxxString);
        fn SetDNSServers(request: Pin<&mut HttpClientRequest>, dns_servers: &Vec<String>);
        fn AddMultiFormData(request: Pin<&mut HttpClientRequest>, data: &MultiFormDataRust);
        fn SetRemoteValidation(self: Pin<&mut HttpClientRequest>, remote_validation: &CxxString);
        fn SetTLSOptions(request: Pin<&mut HttpClientRequest>, tls_options: &TlsConfigRust);
        fn SetServerAuthentication(request: Pin<&mut HttpClientRequest>, server_auth: &ServerAuthentication);
        fn SetHeaderExt(request: Pin<&mut HttpClientRequest>, headers: &EscapedDataRust);
        fn SetCertificatePinning(request: Pin<&mut HttpClientRequest>, certPIN: &CxxString);

        #[namespace = "OHOS::NetStack::HttpClient"]
        type HttpClientTask;

        fn NewHttpClientTask(request: &HttpClientRequest) -> SharedPtr<HttpClientTask>;
        fn GetResponse(self: Pin<&mut HttpClientTask>) -> Pin<&mut HttpClientResponse>;
        fn Start(self: Pin<&mut HttpClientTask>) -> bool;
        fn Cancel(self: Pin<&mut HttpClientTask>);
        fn GetStatus(self: Pin<&mut HttpClientTask>) -> TaskStatus;
        fn OnCallback(task: &SharedPtr<HttpClientTask>, callback: Box<CallbackWrapper>);
        fn GetError(self: Pin<&mut HttpClientTask>) -> Pin<&mut HttpClientError>;
        fn OffDataReceive(self: Pin<&mut HttpClientTask>) -> bool;
        fn OffProgress(self: Pin<&mut HttpClientTask>) -> bool;
        fn OffHeaderReceive(self: Pin<&mut HttpClientTask>) -> bool;
        fn OffHeadersReceive(self: Pin<&mut HttpClientTask>) -> bool;
        fn SetIsHeaderOnce(self: Pin<&mut HttpClientTask>, isOnce: bool);
        fn SetIsHeadersOnce(self: Pin<&mut HttpClientTask>, isOnce: bool);
        fn SetIsRequestInStream(self: Pin<&mut HttpClientTask>, isRequestInStream: bool);
        fn IsRequestInStream(self: Pin<&mut HttpClientTask>) -> bool;

        #[namespace = "OHOS::NetStack::HttpClient"]
        type HttpClientResponse;

        fn GetResponseCode(self: &HttpClientResponse) -> ResponseCode;
        fn GetHeaders(response: Pin<&mut HttpClientResponse>) -> Vec<String>;
        fn GetCookies(self: &HttpClientResponse) -> &CxxString;
        fn GetResult(self: &HttpClientResponse) -> &CxxString;
        fn GetPerformanceTiming(response: Pin<&mut HttpClientResponse>) -> PerformanceInfoRust;
        fn GetExpectDataType(self: &HttpClientResponse) -> HttpDataType;

        #[namespace = "OHOS::NetStack::HttpClient"]
        type HttpClientError;

        fn GetErrorCode(self: &HttpClientError) -> HttpErrorCode;
        fn GetErrorMessage(self: &HttpClientError) -> &CxxString;

        #[namespace = "OHOS::NetStack::CommonUtils"]
        fn HasInternetPermission() -> bool;
    }

    #[repr(i32)]
    enum TaskStatus {
        IDLE,
        RUNNING,
    }

    #[repr(i32)]
    enum ResponseCode {
        NONE = 0,
        OK = 200,
        CREATED,
        ACCEPTED,
        NOT_AUTHORITATIVE,
        NO_CONTENT,
        RESET,
        PARTIAL,
        MULT_CHOICE = 300,
        MOVED_PERM,
        MOVED_TEMP,
        SEE_OTHER,
        NOT_MODIFIED,
        USE_PROXY,
        BAD_REQUEST = 400,
        UNAUTHORIZED,
        PAYMENT_REQUIRED,
        FORBIDDEN,
        NOT_FOUND,
        BAD_METHOD,
        NOT_ACCEPTABLE,
        PROXY_AUTH,
        CLIENT_TIMEOUT,
        CONFLICT,
        GONE,
        LENGTH_REQUIRED,
        PRECON_FAILED,
        ENTITY_TOO_LARGE,
        REQ_TOO_LONG,
        UNSUPPORTED_TYPE,
        INTERNAL_ERROR = 500,
        NOT_IMPLEMENTED,
        BAD_GATEWAY,
        UNAVAILABLE,
        GATEWAY_TIMEOUT,
        VERSION,
    }

    #[repr(i32)]
    enum HttpErrorCode {
        HTTP_NONE_ERR,
        HTTP_PERMISSION_DENIED_CODE = 201,
        HTTP_PARSE_ERROR_CODE = 401,
        HTTP_ERROR_CODE_BASE = 2300000,
        HTTP_UNSUPPORTED_PROTOCOL,
        HTTP_FAILED_INIT,
        HTTP_URL_MALFORMAT,
        HTTP_COULDNT_RESOLVE_PROXY = 2300005,
        HTTP_COULDNT_RESOLVE_HOST,
        HTTP_COULDNT_CONNECT,
        HTTP_WEIRD_SERVER_REPLY,
        HTTP_REMOTE_ACCESS_DENIED,
        HTTP_HTTP2_ERROR = 2300016,
        HTTP_PARTIAL_FILE = 2300018,
        HTTP_WRITE_ERROR = 2300023,
        HTTP_UPLOAD_FAILED = 2300025,
        HTTP_READ_ERROR = 2300026,
        HTTP_OUT_OF_MEMORY,
        HTTP_OPERATION_TIMEDOUT,
        HTTP_POST_ERROR = 2300034,
        HTTP_TASK_CANCELED = 2300042,
        HTTP_TOO_MANY_REDIRECTS = 2300047,
        HTTP_GOT_NOTHING = 2300052,
        HTTP_SEND_ERROR = 2300055,
        HTTP_RECV_ERROR,
        HTTP_SSL_CERTPROBLEM = 2300058,
        HTTP_SSL_CIPHER,
        HTTP_PEER_FAILED_VERIFICATION,
        HTTP_BAD_CONTENT_ENCODING,
        HTTP_FILESIZE_EXCEEDED = 2300063,
        HTTP_REMOTE_DISK_FULL = 2300070,
        HTTP_REMOTE_FILE_EXISTS = 2300073,
        HTTP_SSL_CACERT_BADFILE = 2300077,
        HTTP_REMOTE_FILE_NOT_FOUND,
        HTTP_AUTH_ERROR = 2300094,
        HTTP_UNKNOWN_OTHER_ERROR = 2300999,
    }

    #[repr(i32)]
    enum HttpDataType {
        STRING = 0,
        OBJECT,
        ARRAY_BUFFER,
        NO_DATA_TYPE,
    }

    struct PerformanceInfoRust {
        dns_timing: f64,
        tcp_timing: f64,
        tls_timing: f64,
        first_send_timing: f64,
        first_receive_timing: f64,
        total_timing: f64,
        redirect_timing: f64,
    }
}

impl TryFrom<ffi::TaskStatus> for TaskStatus {
    type Error = ffi::TaskStatus;
    fn try_from(status: ffi::TaskStatus) -> Result<Self, Self::Error> {
        let ret = match status {
            ffi::TaskStatus::IDLE => TaskStatus::Idle,
            ffi::TaskStatus::RUNNING => TaskStatus::Running,
            _ => {
                return Err(status);
            }
        };
        Ok(ret)
    }
}

impl TryFrom<ffi::ResponseCode> for ResponseCode {
    type Error = ffi::ResponseCode;
    fn try_from(value: ffi::ResponseCode) -> Result<Self, Self::Error> {
        let ret = match value {
            ffi::ResponseCode::NONE => ResponseCode::None,
            ffi::ResponseCode::OK => ResponseCode::Ok,
            ffi::ResponseCode::CREATED => ResponseCode::Created,
            ffi::ResponseCode::ACCEPTED => ResponseCode::Accepted,
            ffi::ResponseCode::NOT_AUTHORITATIVE => ResponseCode::NotAuthoritative,
            ffi::ResponseCode::NO_CONTENT => ResponseCode::NoContent,
            ffi::ResponseCode::RESET => ResponseCode::Reset,
            ffi::ResponseCode::PARTIAL => ResponseCode::Partial,
            ffi::ResponseCode::MULT_CHOICE => ResponseCode::MultChoice,
            ffi::ResponseCode::MOVED_PERM => ResponseCode::MovedPerm,
            ffi::ResponseCode::MOVED_TEMP => ResponseCode::MovedTemp,
            ffi::ResponseCode::SEE_OTHER => ResponseCode::SeeOther,
            ffi::ResponseCode::NOT_MODIFIED => ResponseCode::NotModified,
            ffi::ResponseCode::USE_PROXY => ResponseCode::UseProxy,
            ffi::ResponseCode::BAD_REQUEST => ResponseCode::BadRequest,
            ffi::ResponseCode::UNAUTHORIZED => ResponseCode::Unauthorized,
            ffi::ResponseCode::PAYMENT_REQUIRED => ResponseCode::PaymentRequired,
            ffi::ResponseCode::FORBIDDEN => ResponseCode::Forbidden,
            ffi::ResponseCode::NOT_FOUND => ResponseCode::NotFound,
            ffi::ResponseCode::BAD_METHOD => ResponseCode::BadMethod,
            ffi::ResponseCode::NOT_ACCEPTABLE => ResponseCode::NotAcceptable,
            ffi::ResponseCode::PROXY_AUTH => ResponseCode::ProxyAuth,
            ffi::ResponseCode::CLIENT_TIMEOUT => ResponseCode::ClientTimeout,
            ffi::ResponseCode::CONFLICT => ResponseCode::Conflict,
            ffi::ResponseCode::GONE => ResponseCode::Gone,
            ffi::ResponseCode::LENGTH_REQUIRED => ResponseCode::LengthRequired,
            ffi::ResponseCode::PRECON_FAILED => ResponseCode::PreconFailed,
            ffi::ResponseCode::ENTITY_TOO_LARGE => ResponseCode::EntityTooLarge,
            ffi::ResponseCode::REQ_TOO_LONG => ResponseCode::ReqTooLong,
            ffi::ResponseCode::UNSUPPORTED_TYPE => ResponseCode::UnsupportedType,
            ffi::ResponseCode::INTERNAL_ERROR => ResponseCode::InternalError,
            ffi::ResponseCode::NOT_IMPLEMENTED => ResponseCode::NotImplemented,
            ffi::ResponseCode::BAD_GATEWAY => ResponseCode::BadGateway,
            ffi::ResponseCode::UNAVAILABLE => ResponseCode::Unavailable,
            ffi::ResponseCode::GATEWAY_TIMEOUT => ResponseCode::GatewayTimeout,
            ffi::ResponseCode::VERSION => ResponseCode::Version,
            _ => {
                return Err(value);
            }
        };
        Ok(ret)
    }
}

impl TryFrom<ffi::HttpErrorCode> for HttpErrorCode {
    type Error = ffi::HttpErrorCode;
    fn try_from(value: ffi::HttpErrorCode) -> Result<Self, Self::Error> {
        let ret = match value {
            ffi::HttpErrorCode::HTTP_NONE_ERR => HttpErrorCode::HttpNoneErr,
            ffi::HttpErrorCode::HTTP_PERMISSION_DENIED_CODE => {
                HttpErrorCode::HttpPermissionDeniedCode
            }
            ffi::HttpErrorCode::HTTP_PARSE_ERROR_CODE => HttpErrorCode::HttpParseErrorCode,
            ffi::HttpErrorCode::HTTP_ERROR_CODE_BASE => HttpErrorCode::HttpErrorCodeBase,
            ffi::HttpErrorCode::HTTP_UNSUPPORTED_PROTOCOL => HttpErrorCode::HttpUnsupportedProtocol,
            ffi::HttpErrorCode::HTTP_FAILED_INIT => HttpErrorCode::HttpFailedInit,
            ffi::HttpErrorCode::HTTP_URL_MALFORMAT => HttpErrorCode::HttpUrlMalformat,
            ffi::HttpErrorCode::HTTP_COULDNT_RESOLVE_PROXY => {
                HttpErrorCode::HttpCouldntResolveProxy
            }
            ffi::HttpErrorCode::HTTP_COULDNT_RESOLVE_HOST => HttpErrorCode::HttpCouldntResolveHost,
            ffi::HttpErrorCode::HTTP_COULDNT_CONNECT => HttpErrorCode::HttpCouldntConnect,
            ffi::HttpErrorCode::HTTP_WEIRD_SERVER_REPLY => HttpErrorCode::HttpWeirdServerReply,
            ffi::HttpErrorCode::HTTP_REMOTE_ACCESS_DENIED => HttpErrorCode::HttpRemoteAccessDenied,
            ffi::HttpErrorCode::HTTP_HTTP2_ERROR => HttpErrorCode::HttpHttp2Error,
            ffi::HttpErrorCode::HTTP_PARTIAL_FILE => HttpErrorCode::HttpPartialFile,
            ffi::HttpErrorCode::HTTP_WRITE_ERROR => HttpErrorCode::HttpWriteError,
            ffi::HttpErrorCode::HTTP_UPLOAD_FAILED => HttpErrorCode::HttpUploadFailed,
            ffi::HttpErrorCode::HTTP_READ_ERROR => HttpErrorCode::HttpReadError,
            ffi::HttpErrorCode::HTTP_OUT_OF_MEMORY => HttpErrorCode::HttpOutOfMemory,
            ffi::HttpErrorCode::HTTP_OPERATION_TIMEDOUT => HttpErrorCode::HttpOperationTimedout,
            ffi::HttpErrorCode::HTTP_POST_ERROR => HttpErrorCode::HttpPostError,
            ffi::HttpErrorCode::HTTP_TASK_CANCELED => HttpErrorCode::HttpTaskCanceled,
            ffi::HttpErrorCode::HTTP_TOO_MANY_REDIRECTS => HttpErrorCode::HttpTooManyRedirects,
            ffi::HttpErrorCode::HTTP_GOT_NOTHING => HttpErrorCode::HttpGotNothing,
            ffi::HttpErrorCode::HTTP_SEND_ERROR => HttpErrorCode::HttpSendError,
            ffi::HttpErrorCode::HTTP_RECV_ERROR => HttpErrorCode::HttpRecvError,
            ffi::HttpErrorCode::HTTP_SSL_CERTPROBLEM => HttpErrorCode::HttpSslCertproblem,
            ffi::HttpErrorCode::HTTP_SSL_CIPHER => HttpErrorCode::HttpSslCipher,
            ffi::HttpErrorCode::HTTP_PEER_FAILED_VERIFICATION => {
                HttpErrorCode::HttpPeerFailedVerification
            }
            ffi::HttpErrorCode::HTTP_BAD_CONTENT_ENCODING => HttpErrorCode::HttpBadContentEncoding,
            ffi::HttpErrorCode::HTTP_FILESIZE_EXCEEDED => HttpErrorCode::HttpFilesizeExceeded,
            ffi::HttpErrorCode::HTTP_REMOTE_DISK_FULL => HttpErrorCode::HttpRemoteDiskFull,
            ffi::HttpErrorCode::HTTP_REMOTE_FILE_EXISTS => HttpErrorCode::HttpRemoteFileExists,
            ffi::HttpErrorCode::HTTP_SSL_CACERT_BADFILE => HttpErrorCode::HttpSslCacertBadfile,
            ffi::HttpErrorCode::HTTP_REMOTE_FILE_NOT_FOUND => HttpErrorCode::HttpRemoteFileNotFound,
            ffi::HttpErrorCode::HTTP_AUTH_ERROR => HttpErrorCode::HttpAuthError,
            ffi::HttpErrorCode::HTTP_UNKNOWN_OTHER_ERROR => HttpErrorCode::HttpUnknownOtherError,
            _ => {
                return Err(value);
            }
        };
        Ok(ret)
    }
}

impl TryFrom<ffi::HttpDataType> for HttpDataType {
    type Error = ffi::HttpDataType;
    fn try_from(value: ffi::HttpDataType) -> Result<Self, Self::Error> {
        let ret = match value {
            ffi::HttpDataType::STRING => HttpDataType::StringType,
            ffi::HttpDataType::OBJECT => HttpDataType::ObjectType,
            ffi::HttpDataType::ARRAY_BUFFER => HttpDataType::ArrayBuffer,
            ffi::HttpDataType::NO_DATA_TYPE => HttpDataType::None,
            _ => {
                return Err(value);
            }
        };
        Ok(ret)
    }
}

