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

use std::ffi::CStr;

use ani_rs::{
    objects::{AniObject, AniRef},
    AniEnv,
};

use crate::{
    bridge::{HttpRequest, HttpResponseCache},
    cstr,
};

pub const REQUEST_SYNC: &CStr = cstr(b"requestSync\0");
pub const REQUEST_IN_STREAM_SYNC: &CStr = cstr(b"requestInStreamSync\0");
pub const DESTROY: &CStr = cstr(b"destroy\0");
pub const ON: &CStr = cstr(b"on\0");
pub const OFF: &CStr = cstr(b"off\0");
pub const ONCE: &CStr = cstr(b"once\0");
pub const ON_HEADER_RECEIVE_SYNC: &CStr = cstr(b"onHeaderReceiveSync\0");
pub const OFF_HEADER_RECEIVE_SYNC: &CStr = cstr(b"offHeaderReceiveSync\0");

pub fn request_sync<'local>(
    env: AniEnv<'local>,
    _ani_this: AniRef<'local>,
    url: AniObject<'local>,
    options: AniObject<'local>,
) -> AniRef<'local> {
    let http_request = HttpRequest { id: 0 };
    env.serialize(&http_request).unwrap()
}

pub fn request_in_stream_sync<'local>(
    env: AniEnv<'local>,
    _ani_this: AniRef<'local>,
    url: AniObject<'local>,
    options: AniObject<'local>,
) -> f64 {
    let http_request = HttpRequest { id: 0 };
    0.0
}

pub fn destroy<'local>(env: AniEnv<'local>, ani_this: AniRef<'local>) {
    let id = env
        .get_property::<i32>(&ani_this.into(), unsafe {
            CStr::from_bytes_with_nul_unchecked(b"id\0")
        })
        .unwrap();
    panic!("destroy id: {}", id);
}

pub fn on<'local>(
    env: AniEnv<'local>,
    _ani_this: AniRef<'local>,
    event_name: AniObject<'local>,
    callback: AniObject<'local>,
) {
    todo!()
}

pub fn off<'local>(
    env: AniEnv<'local>,
    _ani_this: AniRef<'local>,
    event_name: AniObject<'local>,
    callback: AniObject<'local>,
) {
}

pub fn once<'local>(
    env: AniEnv<'local>,
    _ani_this: AniRef<'local>,
    event_name: AniObject<'local>,
    callback: AniObject<'local>,
) {
    todo!()
}

pub fn on_header_receive_sync<'local>(
    env: AniEnv<'local>,
    _ani_this: AniRef<'local>,
) -> AniRef<'local> {
    let http_request = HttpRequest { id: 0 };
    env.serialize(&http_request).unwrap()
}

pub fn off_header_receive_sync<'local>(
    env: AniEnv<'local>,
    _ani_this: AniRef<'local>,
) -> AniRef<'local> {
    let http_request = HttpRequest { id: 0 };
    env.serialize(&http_request).unwrap()
}
