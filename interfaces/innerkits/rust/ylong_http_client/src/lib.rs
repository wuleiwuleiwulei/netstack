/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! This crate is an adapter of `Reqwest` and `Ylong`, you can choose the
//! underlying implementation.

#[cfg(feature = "reqwest_impl")]
mod reqwest_impl;

#[cfg(feature = "reqwest_impl")]
pub use reqwest_impl::*;

#[cfg(feature = "ylong_impl")]
pub use ylong_http_client_inner::*;
