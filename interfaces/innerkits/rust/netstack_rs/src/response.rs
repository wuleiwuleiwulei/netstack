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

use std::collections::HashMap;
use std::pin::Pin;

use cxx::SharedPtr;

use crate::task::RequestTask;
use crate::wrapper;
use crate::wrapper::ffi::{GetHeaders, HttpClientResponse, HttpClientTask};

/// http client response
pub struct Response<'a> {
    inner: ResponseInner<'a>,
}

impl<'a> Response<'a> {
    /// Get Response Code
    pub fn status(&self) -> ResponseCode {
        let response = self.inner.to_response();
        response.GetResponseCode().try_into().unwrap_or_default()
    }

    pub fn headers(&self) -> HashMap<String, String> {
        let ptr = self.inner.to_response() as *const HttpClientResponse as *mut HttpClientResponse;
        let p = unsafe { Pin::new_unchecked(ptr.as_mut().unwrap()) };

        let mut headers = GetHeaders(p).into_iter();
        let mut ret = HashMap::new();
        loop {
            if let Some(key) = headers.next() {
                if let Some(value) = headers.next() {
                    ret.insert(key.to_lowercase(), value);
                    continue;
                }
            }
            break;
        }
        ret
    }

    pub fn cookies(&self) -> String {
        let response = self.inner.to_response();
        response.GetCookies().to_string()
    }

    pub fn get_result(&self) -> String {
        let response = self.inner.to_response();
        response.GetResult().to_string()
    }

    pub fn performance_timing(&self) -> PerformanceInfo {
        let ptr = self.inner.to_response() as *const HttpClientResponse as *mut HttpClientResponse;
        let p = unsafe { Pin::new_unchecked(ptr.as_mut().unwrap()) };
        let res = wrapper::ffi::GetPerformanceTiming(p);
        PerformanceInfo {
            dns_timing: res.dns_timing,
            tcp_timing: res.tcp_timing,
            tls_timing: res.tls_timing,
            first_send_timing: res.first_send_timing,
            first_receive_timing: res.first_receive_timing,
            total_timing: res.total_timing,
            redirect_timing: res.redirect_timing,
        }
    }

    pub fn get_expect_data_type(&self) -> HttpDataType {
        let response = self.inner.to_response();
        let data_type = HttpDataType::try_from(response.GetExpectDataType()).unwrap_or_default();
        data_type
    }

    pub(crate) fn from_ffi(inner: &'a HttpClientResponse) -> Self {
        Self {
            inner: ResponseInner::Ref(inner),
        }
    }

    pub(crate) fn from_shared(inner: SharedPtr<HttpClientTask>) -> Self {
        Self {
            inner: ResponseInner::Shared(inner),
        }
    }
}

enum ResponseInner<'a> {
    Ref(&'a HttpClientResponse),
    Shared(SharedPtr<HttpClientTask>),
}

impl<'a> ResponseInner<'a> {
    fn to_response(&self) -> &HttpClientResponse {
        match self {
            ResponseInner::Ref(inner) => inner,
            ResponseInner::Shared(inner) => RequestTask::pin_mut(inner)
                .GetResponse()
                .into_ref()
                .get_ref(),
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub enum ResponseCode {
    #[default]
    None = 0,
    Ok = 200,
    Created,
    Accepted,
    NotAuthoritative,
    NoContent,
    Reset,
    Partial,
    MultChoice = 300,
    MovedPerm,
    MovedTemp,
    SeeOther,
    NotModified,
    UseProxy,
    BadRequest = 400,
    Unauthorized,
    PaymentRequired,
    Forbidden,
    NotFound,
    BadMethod,
    NotAcceptable,
    ProxyAuth,
    ClientTimeout,
    Conflict,
    Gone,
    LengthRequired,
    PreconFailed,
    EntityTooLarge,
    ReqTooLong,
    UnsupportedType,
    InternalError = 500,
    NotImplemented,
    BadGateway,
    Unavailable,
    GatewayTimeout,
    Version,
}

pub struct PerformanceInfo {
    pub dns_timing: f64,
    pub tcp_timing: f64,
    pub tls_timing: f64,
    pub first_send_timing: f64,
    pub first_receive_timing: f64,
    pub total_timing: f64,
    pub redirect_timing: f64,
}

/// http data type
#[derive(Debug, Default)]
pub enum HttpDataType {
    StringType = 0,
    ObjectType,
    ArrayBuffer,
    #[default]
    None,
}

impl HttpDataType {
    pub fn to_i32(&self) -> i32 {
        match self {
            HttpDataType::StringType => 0,
            HttpDataType::ObjectType => 1,
            HttpDataType::ArrayBuffer => 2,
            _=> -1,
        }
    }
}