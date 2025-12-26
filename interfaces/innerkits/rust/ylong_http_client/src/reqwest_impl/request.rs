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

use crate::reqwest_impl::async_impl::MultiPart;
use crate::reqwest_impl::{Method, Version};
use crate::{ErrorKind, HttpClientError};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Url;

/// HTTP request implementation.
///
/// Request is a message type that can be sent from a HTTP client to a HTTP server.
///
/// # Examples
///
/// ```
/// use ylong_http_client::{Method, Request};
///
/// let request = Request::builder()
///     .method(Method::GET)
///     .url("www.example.com")
///     .body("Hello World".as_bytes());
/// ```
pub struct Request<T> {
    pub(crate) inner: RequestInner,
    pub(crate) body: T,
}

impl Request<()> {
    /// Creates a `RequestBuilder` that can construct a `Request`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::Request;
    ///
    /// let builder = Request::builder();
    /// ```
    pub fn builder() -> RequestBuilder {
        RequestBuilder::new()
    }
}

/// A builder that can construct a `Request`.
///
/// # Examples
///
/// ```
/// use ylong_http_client::RequestBuilder;
///
/// let builder = RequestBuilder::new();
/// ```
pub struct RequestBuilder {
    inner: Result<RequestInner, HttpClientError>,
}

impl RequestBuilder {
    /// Creates a `RequestBuilder`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::RequestBuilder;
    ///
    /// let builder = RequestBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            inner: Ok(RequestInner::default()),
        }
    }

    /// Sets `Method` of this request.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::{Method, RequestBuilder};
    ///
    /// let builder = RequestBuilder::new().method(Method::GET);
    /// ```
    pub fn method(mut self, method: Method) -> Self {
        self.inner = self.inner.map(|mut r| {
            r.method = method;
            r
        });
        self
    }

    /// Sets `Url` of this request.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::{Method, RequestBuilder};
    ///
    /// let builder = RequestBuilder::new().url("www.example.com");
    /// ```
    pub fn url(mut self, url: &str) -> Self {
        self.inner = self.inner.and_then(|mut r| {
            r.url = Url::parse(url)
                .map_err(|e| HttpClientError::new_with_cause(ErrorKind::Build, Some(e)))?;
            Ok(r)
        });
        self
    }

    /// Adds a header to this request.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::RequestBuilder;
    ///
    /// let builder = RequestBuilder::new().header("Content-Length", "100");
    /// ```
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.inner = self.inner.and_then(|mut r| {
            r.headers.insert(
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|e| HttpClientError::new_with_cause(ErrorKind::Build, Some(e)))?,
                value
                    .parse()
                    .map_err(|e| HttpClientError::new_with_cause(ErrorKind::Build, Some(e)))?,
            );
            Ok(r)
        });
        self
    }

    /// Sets the `Version` of the request.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::{RequestBuilder, Version};
    ///
    /// let builder = RequestBuilder::new().version(Version::HTTP_11);
    /// ```
    pub fn version(mut self, version: Version) -> Self {
        self.inner = self.inner.map(|mut r| {
            r.version = version;
            r
        });
        self
    }

    /// Creates a `Request` that uses this `RequestBuilder` configuration and
    /// the provided body.
    ///
    /// # Error
    ///
    /// This method fails if some configurations are wrong.
    ///
    /// # Examples
    ///
    /// ```
    /// use ylong_http_client::RequestBuilder;
    ///
    /// let request = RequestBuilder::new().body("HelloWorld".as_bytes()).unwrap();
    /// ```
    pub fn body<T: Into<reqwest::Body>>(self, body: T) -> Result<Request<T>, HttpClientError> {
        Ok(Request {
            inner: self.inner?,
            body,
        })
    }

    /// Creates a `Request` that uses this `RequestBuilder` configuration and
    /// the provided `Multipart`. You can also provide a `Uploader<Multipart>`
    /// as the body.
    ///
    /// # Error
    ///
    /// This method fails if some configurations are wrong.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ylong_http_client::async_impl::{MultiPart, Part};
    /// # use ylong_http_client::RequestBuilder;
    ///
    /// # fn create_request_with_multipart(multipart: MultiPart) {
    /// let request = RequestBuilder::new().multipart(multipart).unwrap();
    /// # }
    /// ```
    pub fn multipart<T>(self, body: T) -> Result<Request<T>, HttpClientError>
    where
        T: Into<reqwest::Body> + AsRef<MultiPart>,
    {
        let value = format!("multipart/form-data; boundary={}", body.as_ref().boundary());

        let mut inner = self.inner?;
        inner.headers.insert(
            "Content-Type",
            HeaderValue::from_str(value.as_str())
                .map_err(|e| HttpClientError::new_with_cause(ErrorKind::Build, Some(e)))?,
        );

        if let Some(size) = body.as_ref().total_bytes() {
            inner.headers.insert(
                "Content-Length",
                HeaderValue::from_str(format!("{}", size).as_str())
                    .map_err(|e| HttpClientError::new_with_cause(ErrorKind::Build, Some(e)))?,
            );
        }

        Ok(Request { inner, body })
    }
}

impl Default for RequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct RequestInner {
    pub(crate) method: Method,
    pub(crate) url: Url,
    pub(crate) headers: HeaderMap,
    pub(crate) version: Version,
}

impl Default for RequestInner {
    fn default() -> Self {
        Self {
            method: Default::default(),
            url: Url::parse("https://example.net").unwrap(),
            headers: Default::default(),
            version: Default::default(),
        }
    }
}

/// Body trait implementation.
pub trait Body: Into<reqwest::Body> {}

impl<T: Into<reqwest::Body>> Body for T {}
