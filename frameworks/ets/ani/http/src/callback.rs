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

use ani_rs::{business_error::BusinessError, objects::{
        GlobalRefAsyncCallback,
        GlobalRefCallback,
        AniObject,
        JsonValue,
        AniRef
    },
    typed_array::ArrayBuffer, AniVm, AniEnv, global::GlobalRef};
use netstack_rs::{error::HttpErrorCode, request::RequestCallback};

use crate::bridge::{
    convert_to_business_error, DataReceiveProgressInfo, DataSendProgressInfo, HttpDataType,
    HttpResponse, PerformanceTiming, ResponseCodeOutput
};

pub struct TaskCallback {
    pub on_response: Option<GlobalRefAsyncCallback<(HttpResponse,)>>,
    pub on_response_in_stream: Option<GlobalRefAsyncCallback<(i32,)>>,
    pub on_header_receive: Option<GlobalRefAsyncCallback<(String,)>>,
    pub on_headers_receive: Option<GlobalRefCallback<(HashMap<String, String>,)>>,
    pub on_data_receive: Option<GlobalRefCallback<(Vec<u8>,)>>,

    pub on_data_end: Option<GlobalRefCallback<()>>,
    pub on_data_receive_progress: Option<GlobalRefCallback<(DataReceiveProgressInfo,)>>,
    pub on_data_send_progress: Option<GlobalRefCallback<(DataSendProgressInfo,)>>,
}

impl TaskCallback {
    pub fn new() -> Self {
        Self {
            on_response: None,
            on_response_in_stream: None,
            on_header_receive: None,
            on_headers_receive: None,
            on_data_receive: None,

            on_data_end: None,
            on_data_receive_progress: None,
            on_data_send_progress: None,
        }
    }
}

impl RequestCallback for TaskCallback {
    fn on_success(&mut self, response: netstack_rs::response::Response, is_request_in_stream: bool) {
        let code = response.status() as i32;
        let string_data = response.get_result();
        let data_type = response.get_expect_data_type();
        let header = response.headers();
        let cookies = response.cookies();
        let performance_timing = PerformanceTiming::from(response.performance_timing());

        if is_request_in_stream {
            if let Some(callback) = self.on_response_in_stream.take() {
                ani_rs::send_event_from_closure(move || {
                    callback.execute(None, (code,));
                }, "http_response_instream_success_callback").unwrap();
            }
        } else {
            if let Some(global_callback) = self.on_response.take() {
                ani_rs::send_event_from_closure(move || {
                    let env = AniVm::get_instance().get_env().unwrap();
                    let ret = match data_type {
                        netstack_rs::response::HttpDataType::StringType => {
                            let s_ref = env.serialize(&string_data).unwrap().into_global(&env).unwrap();
                            let ets_response = HttpResponse::new(s_ref, HttpDataType::String,
                                code, header, cookies, performance_timing);
                            global_callback.execute(None, (ets_response,));
                        },
                        netstack_rs::response::HttpDataType::ObjectType => {
                            let json_value = JsonValue::parse(&env, &string_data).unwrap();
                            let json_global = AniRef::from(json_value).into_global(&env).unwrap();
                            let ets_response = HttpResponse::new(json_global, HttpDataType::Object,
                                code, header, cookies, performance_timing);
                            global_callback.execute(None, (ets_response,));
                        },
                        netstack_rs::response::HttpDataType::ArrayBuffer => {
                            let array_buffer = ArrayBuffer::new_with_vec(string_data.as_bytes().to_vec());
                            let buffer_global = env.serialize(&array_buffer).unwrap().into_global(&env).unwrap();
                            let ets_response = HttpResponse::new(buffer_global, HttpDataType::ArrayBuffer,
                                code, header, cookies, performance_timing);
                            global_callback.execute(None, (ets_response,));
                        },
                        _ => {
                            info!("send_event_from_closure httpDataType is None");
                        }
                    };
                }, "http_response_success_callback").unwrap();
            }
        }

        if let Some(callback) = self.on_data_end.take() {
            callback.execute(());
        }
    }

    fn on_fail(
        &mut self,
        response: netstack_rs::response::Response,
        error: netstack_rs::error::HttpClientError,
        is_request_in_stream: bool
    ) {
        let code = response.status() as i32;
        let business_error = convert_to_business_error(&error);
        error!("OnFiled. response_code = {}, error = {:?}", code, error);
        let string_data = response.get_result();
        if is_request_in_stream {
            if let Some(callback) = self.on_response_in_stream.take() {
                ani_rs::send_event_from_closure(move || {
                    callback.execute(Some(business_error), (code,));
                }, "http_response_instream_failed_callback").unwrap();
            }
        } else {
            if let Some(callback) = self.on_response.take() {
                ani_rs::send_event_from_closure(move || {
                    let env = AniVm::get_instance().get_env().unwrap();
                    let s_ref = env.serialize(&string_data).unwrap().into_global(&env).unwrap();
                    let ets_response = HttpResponse::new(s_ref, HttpDataType::String,
                        code, HashMap::new(),  String::new(), PerformanceTiming::new());
                    callback.execute(Some(business_error), (ets_response,));
                }, "http_response_failed_callback").unwrap();
            }
        }

        if let Some(callback) = self.on_data_end.take() {
            callback.execute(());
        }
    }

    fn on_cancel(&mut self, response: netstack_rs::response::Response, is_request_in_stream: bool) {
        let code = response.status() as i32;
        let business_error = BusinessError::new(
            HttpErrorCode::HttpWriteError as i32,
            "request canceled".to_string(),
        );
        let string_data = response.get_result();
        if is_request_in_stream {
            if let Some(callback) = self.on_response_in_stream.take() {
                ani_rs::send_event_from_closure(move || {
                    callback.execute(Some(business_error), (code,));
                }, "http_response_instream_cancel_callback").unwrap();
            }
        } else {
            if let Some(callback) = self.on_response.take() {
                ani_rs::send_event_from_closure(move || {
                    let env = AniVm::get_instance().get_env().unwrap();
                    let s_ref = env.serialize(&string_data).unwrap().into_global(&env).unwrap();
                    let ets_response = HttpResponse::new(s_ref, HttpDataType::String,
                        code, HashMap::new(),  String::new(), PerformanceTiming::new());
                    callback.execute(Some(business_error), (ets_response,));
                }, "http_response_cancel_callback").unwrap();
            }
        }
    }

    fn on_data_receive(&mut self, data: &[u8], mut task: netstack_rs::task::RequestTask) {
        if let Some(callback) = self.on_data_receive.as_ref() {
            info!("on_data_receive callback set");
            let data_bytes: Vec<u8> = data.to_vec();
            callback.execute((data_bytes,));
        }
    }

    fn on_progress(&mut self, dl_total: u64, dl_now: u64, ul_total: u64, ul_now: u64) {
        if let Some(callback) = self.on_data_send_progress.as_ref() {
            if (ul_total != 0 && ul_total >= ul_now) {
                let send_info = DataSendProgressInfo {
                    send_size: ul_now as i32,
                    total_size: ul_total as i32,
                };
                callback.execute((send_info,));
            }
        }
        if let Some(callback) = self.on_data_receive_progress.as_ref() {
            if (dl_total != 0 && dl_total >= dl_now) {
                let receive_info = DataReceiveProgressInfo {
                    receive_size: dl_now as i32,
                    total_size: dl_total as i32,
                };
                callback.execute((receive_info,));
            }
        }
    }

    fn on_header_receive(&mut self, header: String) {
        if let Some(callback) = self.on_header_receive.as_ref() {
            info!("on_header_receive callback set");
            callback.execute(None, (header.clone(),));
        }
    }

    fn on_headers_receive(&mut self, headers: HashMap<String, String>) {
        if let Some(callback) = self.on_headers_receive.as_ref() {
            info!("on_headers_receive callback set");
            callback.execute((headers.clone(),));
        }
    }
}
