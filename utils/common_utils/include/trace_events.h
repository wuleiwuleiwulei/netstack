/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATION_NETSTACK_TRACE_EVENTS_H
#define COMMUNICATION_NETSTACK_TRACE_EVENTS_H
namespace OHOS::NetStack {
    struct TraceEvents {
        static constexpr const char* FETCH = "HttpRequest::FETCH";
        static constexpr const char* QUEUE = "HttpRequest::QUEUE";
        static constexpr const char* DNS = "HttpRequest::DNS";
        static constexpr const char* TCP = "HttpRequest::TCP";
        static constexpr const char* TLS = "HttpRequest::TLS";
        static constexpr const char* SENDING = "HttpRequest::SENDING";
        static constexpr const char* RECEIVING = "HttpRequest::RECEIVING";
        static constexpr const char* NATIVE = "HttpRequest::NATIVE";
        static constexpr const char* NAPI_QUEUE = "HttpRequest::NAPI_QUEUE";
    };
} // namespace OHOS::NetStack::RequestTracer
#endif // COMMUNICATION_NETSTACK_TRACE_EVENTS_H