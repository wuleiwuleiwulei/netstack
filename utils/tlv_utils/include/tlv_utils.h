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
#ifndef COMMUNICATION_NETSTACK_TLV_UTILS_H
#define COMMUNICATION_NETSTACK_TLV_UTILS_H

#include <cstdint>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

namespace OHOS::NetStack {

#define TLV_OK 0
#define TLV_ERR 1001
#define TLV_ERR_INVALID_PARA 1002
#define TLV_ERR_PARSE_PAYLOAD_ERR 1003
#define TLV_ERR_BUFF_NO_ENOUGH 1004

struct DfxMessage {
    uint64_t requestBeginTime_ = 0;
    uint64_t dnsEndTime_ = 0;
    uint64_t tcpConnectEndTime_ = 0;
    uint64_t tlsHandshakeEndTime_ = 0;
    uint64_t firstSendTime_ = 0;
    uint64_t firstRecvTime_ = 0;
    uint64_t requestEndTime_ = 0;
    std::string requestId_;
    std::string requestUrl_;
    std::string requestMethod_;
    std::string requestHeader_;
    uint32_t responseStatusCode_ = 0;
    std::string responseHeader_;
    std::string responseEffectiveUrl_;
    std::string responseIpAddress_;
    std::string responseHttpVersion_;
    std::string responseReasonPhrase_;
    std::string responseBody_;
};

enum Type : int32_t {
    INVALID = 0,
    U64 = 1,
    U32,
    STRING,
};

typedef struct TlvCommon {
    uint32_t tag_;
    uint32_t len_;
    void *value_;
} TlvCommon;

class TlvUtils {
public:
    static uint32_t Encode(DfxMessage &msg, void *data, uint32_t &dataSize);
    static uint32_t Decode(DfxMessage &msg, void *data, uint32_t dataSize);

private:
    static uint8_t *GetNextTlv(const uint8_t *buffer);
    static uint8_t *ParseTlv(const uint8_t *buffer, TlvCommon *tlv, const uint8_t *boundary, uint32_t *retCode);
    static uint8_t *AppendTlv(uint8_t *buffer, const TlvCommon *tlv, const uint8_t *boundary, uint32_t *retCode);
    static uint32_t Serialize(const TlvCommon *tlv, uint32_t tlvCount, uint8_t *buff, uint32_t maxBuffSize,
                              uint32_t *buffSize);
    static uint32_t Deserialize(const uint8_t *buff, uint32_t buffSize, TlvCommon *tlv, uint32_t maxTlvCount,
                                uint32_t *tlvCount);
    static uint32_t GenerateTlv(DfxMessage &msg, TlvCommon *tlv, uint32_t *tlvCount);
    static uint32_t Parse(DfxMessage &msg, TlvCommon *tlvs, uint32_t tlvCount);
};
}

#ifdef __cplusplus
}
#endif

#endif //COMMUNICATION_NETSTACK_TLV_UTILS_H