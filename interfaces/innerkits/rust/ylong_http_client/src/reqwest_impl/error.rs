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

use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

/// Errors that may occur in this crate.
pub struct HttpClientError {
    kind: ErrorKind,
    cause: Option<Box<dyn Error + Send + Sync>>,
}

impl HttpClientError {
    /// Creates a `UserAborted` error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::HttpClientError;
    ///
    /// let user_aborted = HttpClientError::user_aborted();
    /// ```
    pub fn user_aborted() -> Self {
        Self {
            kind: ErrorKind::UserAborted,
            cause: None,
        }
    }

    /// Creates an `Other` error.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::HttpClientError;
    ///
    /// let other = HttpClientError::user_aborted();
    /// ```
    pub fn other<T: Into<Box<dyn Error + Send + Sync>>>(cause: Option<T>) -> Self {
        Self {
            kind: ErrorKind::Other,
            cause: cause.map(Into::into),
        }
    }

    /// Gets the `ErrorKind` of this `HttpClientError`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::{ErrorKind, HttpClientError};
    ///
    /// let user_aborted = HttpClientError::user_aborted();
    /// assert_eq!(user_aborted.error_kind(), ErrorKind::UserAborted);
    /// ```
    pub fn error_kind(&self) -> ErrorKind {
        self.kind
    }

    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self { kind, cause: None }
    }

    pub(crate) fn new_with_cause<T>(kind: ErrorKind, cause: Option<T>) -> Self
    where
        T: Into<Box<dyn Error + Send + Sync>>,
    {
        Self {
            kind,
            cause: cause.map(Into::into),
        }
    }
}

impl From<reqwest::Error> for HttpClientError {
    fn from(err: reqwest::Error) -> Self {
        let kind = match &err {
            e if e.is_builder() => ErrorKind::Build,
            e if e.is_timeout() => ErrorKind::Timeout,
            e if e.is_request() => ErrorKind::Request,
            e if e.is_redirect() => ErrorKind::Redirect,
            e if e.is_connect() => ErrorKind::Connect,
            e if e.is_body() => ErrorKind::BodyTransfer,
            e if e.is_decode() => ErrorKind::BodyDecode,
            _ => ErrorKind::Other,
        };
        Self {
            kind,
            cause: Some(Box::new(err)),
        }
    }
}

impl Debug for HttpClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClientError")
            .field("kind", &self.kind.as_str())
            .field("cause", &self.cause)
            .finish()
    }
}

impl Display for HttpClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind.as_str())?;
        if let Some(cause) = self.cause.as_ref() {
            f.write_str(":")?;
            return Display::fmt(cause, f);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Build,
    Connect,
    Request,
    Redirect,
    BodyTransfer,
    BodyDecode,
    ConnectionUpgrade,
    UserAborted,
    Timeout,
    Other,
}

impl ErrorKind {
    /// Gets the string info of this `ErrorKind`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::ErrorKind;
    ///
    /// assert_eq!(ErrorKind::UserAborted.as_str(), "User Aborted Error");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Build => "Build Error",
            Self::Connect => "Connect Error",
            Self::Request => "Request Error",
            Self::Redirect => "Redirect Error",
            Self::BodyTransfer => "Body Transfer Error",
            Self::BodyDecode => "Body Decode Error",
            Self::ConnectionUpgrade => "Connection Upgrade Error",
            Self::UserAborted => "User Aborted Error",
            Self::Timeout => "Timeout Error",
            Self::Other => "Other Error",
        }
    }
}
