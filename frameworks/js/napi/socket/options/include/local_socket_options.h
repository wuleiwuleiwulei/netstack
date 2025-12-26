/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef LOCAL_SOCKET_OPTIONS_H
#define LOCAL_SOCKET_OPTIONS_H

#include <string>

#include "extra_options_base.h"

namespace OHOS::NetStack::Socket {
class LocalSocketRemoteInfo {
public:
    LocalSocketRemoteInfo() {}
    virtual ~LocalSocketRemoteInfo() {}

    void SetAddress(const std::string &address)
    {
        address_ = address;
    }
    void SetSize(uint32_t size)
    {
        size_ = size;
    }
    [[nodiscard]] const std::string &GetAddress() const
    {
        return address_;
    }
    [[nodiscard]] uint32_t GetSize() const
    {
        return size_;
    }

private:
    std::string address_;
    uint32_t size_ = 0;
};

class LocalSocketOptions {
public:
    LocalSocketOptions() {}
    ~LocalSocketOptions() {}
    void SetBuffer(const std::string &buffer);
    void SetBuffer(void *data, size_t size);
    void SetEncoding(const std::string &encoding)
    {
        encoding_ = encoding;
    }
    [[nodiscard]] const std::string &GetBufferRef() const;

private:
    std::string buffer_;
    std::string encoding_;
};

class LocalExtraOptions : public ExtraOptionsBase {
public:
    bool AlreadySetRecvBufSize() const
    {
        return recvBufSizeFlag_;
    }
    bool AlreadySetSendBufSize() const
    {
        return sendBufSizeFlag_;
    }
    bool AlreadySetTimeout() const
    {
        return timeoutFlag_;
    }
    void SetRecvBufSizeFlag(bool flag)
    {
        recvBufSizeFlag_ = flag;
    }
    void SetSendBufSizeFlag(bool flag)
    {
        sendBufSizeFlag_ = flag;
    }
    void SetTimeoutFlag(bool flag)
    {
        timeoutFlag_ = flag;
    }

private:
    bool recvBufSizeFlag_ = false;
    bool sendBufSizeFlag_ = false;
    bool timeoutFlag_ = false;
};
} // namespace OHOS::NetStack::Socket

#endif