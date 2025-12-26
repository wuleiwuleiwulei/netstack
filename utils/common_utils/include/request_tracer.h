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

#ifndef NETSTACK_REQUEST_TRACER_H
#define NETSTACK_REQUEST_TRACER_H
#include <optional>
#include <string>
namespace OHOS::NetStack::RequestTracer {
    class Trace final {
    public:
        Trace(const std::string &className, int32_t idNum);
        explicit Trace(const std::string &className);
        ~Trace();
        void Tracepoint(const std::string &stage);
        void Finish();

        static int32_t GenerateId();
    private:
        std::string className_;
        std::optional<std::string> stageName_;
        [[maybe_unused]] int32_t idNum_;
    };
} // namespace OHOS::NetStack::RequestTracer
#endif // NETSTACK_REQUEST_TRACER_H