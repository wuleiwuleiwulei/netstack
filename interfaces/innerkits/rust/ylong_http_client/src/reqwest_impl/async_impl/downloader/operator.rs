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

use crate::HttpClientError;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A `DownloadOperator` represents structures that can write downloaded data to
/// somewhere and display progress.
///
/// You can implement `DownloadOperator` for your structures and pass it to a
/// `Downloader`. Then the `Downloader` can use the `download` and `progress`
/// methods to help you download the body part of a response.
///
/// # Examples
///
/// ```
/// # use std::pin::Pin;
/// # use std::task::{Context, Poll};
/// # use ylong_http_client::async_impl::DownloadOperator;
/// # use ylong_http_client::HttpClientError;
///
/// // Creates your own operator.
/// struct MyDownloadOperator;
///
/// // Implements `DownloaderOperator` for your structures.
/// impl DownloadOperator for MyDownloadOperator {
///     fn poll_download(
///         self: Pin<&mut Self>,
///         cx: &mut Context<'_>,
///         data: &[u8],
///     ) -> Poll<Result<usize, HttpClientError>> {
///         todo!()
///     }
///
///     fn poll_progress(
///         self: Pin<&mut Self>,
///         cx: &mut Context<'_>,
///         downloaded: u64,
///         total: Option<u64>
///     ) -> Poll<Result<(), HttpClientError>> {
///         // Writes your customize method.
///         todo!()
///     }
/// }
/// ```
pub trait DownloadOperator {
    /// The download method that you need to implement. You need to write the
    /// data read from the body to the specified location in this method.
    fn poll_download(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, HttpClientError>>;

    /// The progress method that you need to implement. You need to perform some
    /// operations in this method based on the number of bytes downloaded and
    /// the total file size.
    fn poll_progress(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _downloaded: u64,
        _total: Option<u64>,
    ) -> Poll<Result<(), HttpClientError>> {
        Poll::Ready(Ok(()))
    }

    /// Creates a `DownloadFuture`.
    fn download<'a, 'b>(&'a mut self, data: &'b [u8]) -> DownloadFuture<'a, 'b, Self>
    where
        Self: Unpin + Sized + 'a + 'b,
    {
        DownloadFuture {
            operator: self,
            data,
        }
    }

    /// Creates a `ProgressFuture`.
    fn progress<'a>(&'a mut self, downloaded: u64, total: Option<u64>) -> ProgressFuture<'a, Self>
    where
        Self: Unpin + Sized + 'a,
    {
        ProgressFuture {
            operator: self,
            downloaded,
            total,
        }
    }
}

impl<T> DownloadOperator for &mut T
where
    T: DownloadOperator + Unpin,
{
    fn poll_download(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, HttpClientError>> {
        Pin::new(&mut **self).poll_download(cx, data)
    }

    fn poll_progress(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        downloaded: u64,
        total: Option<u64>,
    ) -> Poll<Result<(), HttpClientError>> {
        Pin::new(&mut **self).poll_progress(cx, downloaded, total)
    }
}

/// A future that execute `poll_download` method.
pub struct DownloadFuture<'a, 'b, T> {
    operator: &'a mut T,
    data: &'b [u8],
}

impl<'a, 'b, T> Future for DownloadFuture<'a, 'b, T>
where
    T: DownloadOperator + Unpin + 'a,
{
    type Output = Result<usize, HttpClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let fut = self.get_mut();
        Pin::new(&mut fut.operator).poll_download(cx, fut.data)
    }
}

/// A future that execute `poll_progress` method.
pub struct ProgressFuture<'a, T> {
    operator: &'a mut T,
    downloaded: u64,
    total: Option<u64>,
}

impl<'a, T> Future for ProgressFuture<'a, T>
where
    T: DownloadOperator + Unpin + 'a,
{
    type Output = Result<(), HttpClientError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let fut = self.get_mut();
        Pin::new(&mut fut.operator).poll_progress(cx, fut.downloaded, fut.total)
    }
}

/// A default download operator that display messages on console.
pub struct Console;

impl DownloadOperator for Console {
    fn poll_download(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, HttpClientError>> {
        println!("{:?}", data);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_progress(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        downloaded: u64,
        _total: Option<u64>,
    ) -> Poll<Result<(), HttpClientError>> {
        println!("progress: download-{} bytes", downloaded);
        Poll::Ready(Ok(()))
    }
}
