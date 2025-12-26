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

#include "lru_cache_disk_handler.h"

#include <thread>

#include "netstack_log.h"

namespace OHOS::NetStack::Http {
LRUCacheDiskHandler::LRUCacheDiskHandler(std::string fileName, size_t capacity)
    : diskHandler_(std::move(fileName)),
      capacity_(std::max<size_t>(std::min<size_t>(MAX_DISK_CACHE_SIZE, capacity), MIN_DISK_CACHE_SIZE))
{
}

void LRUCacheDiskHandler::SetCapacity(size_t capacity)
{
    capacity_ = std::max<size_t>(std::min<size_t>(MAX_DISK_CACHE_SIZE, capacity), MIN_DISK_CACHE_SIZE);
    WriteCacheToJsonFile();
}

void LRUCacheDiskHandler::Delete()
{
    cache_.Clear();
    diskHandler_.Delete();
}

cJSON* LRUCacheDiskHandler::ReadJsonValueFromFile()
{
    std::string jsonStr = diskHandler_.Read();
    cJSON *root = cJSON_Parse(jsonStr.c_str());
    if (root == nullptr) {
        NETSTACK_LOGE("parse json not success, maybe file is broken");
        return nullptr;
    }
    return root;
}

void LRUCacheDiskHandler::WriteJsonValueToFile(const cJSON *root)
{
    char *jsonStr = cJSON_Print(root);
    if (jsonStr == nullptr) {
        NETSTACK_LOGE("write json failed");
        return;
    }
    std::string s = jsonStr;
    diskHandler_.Write(s);
    cJSON_free(jsonStr);
}

void LRUCacheDiskHandler::WriteCacheToJsonFile()
{
    LRUCache oldCache(capacity_);
    cJSON *readRoot = ReadJsonValueFromFile();
    oldCache.ReadCacheFromJsonValue(readRoot);
    cJSON_Delete(readRoot);
    oldCache.MergeOtherCache(cache_);
    cJSON *writeRoot = oldCache.WriteCacheToJsonValue();
    WriteJsonValueToFile(writeRoot);
    cJSON_Delete(writeRoot);
    cache_.Clear();
}

void LRUCacheDiskHandler::ReadCacheFromJsonFile()
{
    cJSON *root = ReadJsonValueFromFile();
    cache_.ReadCacheFromJsonValue(root);
    cJSON_Delete(root);
}

std::unordered_map<std::string, std::string> LRUCacheDiskHandler::Get(const std::string &key)
{
    auto valueFromMemory = cache_.Get(key);
    if (!valueFromMemory.empty()) {
        return valueFromMemory;
    }

    LRUCache diskCache(capacity_);
    cJSON *root = ReadJsonValueFromFile();
    diskCache.ReadCacheFromJsonValue(root);
    cJSON_Delete(root);
    auto valueFromDisk = diskCache.Get(key);
    cache_.Put(key, valueFromDisk);
    return valueFromDisk;
}

void LRUCacheDiskHandler::Put(const std::string &key, const std::unordered_map<std::string, std::string> &value)
{
    cache_.Put(key, value);
}
} // namespace OHOS::NetStack::Http
