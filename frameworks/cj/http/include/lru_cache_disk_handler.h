/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LRU_CACHE_DISK_HANDLER_H
#define LRU_CACHE_DISK_HANDLER_H

#include <list>
#include <string>
#include <unordered_map>
#include "cJSON.h"
#include <mutex>

namespace OHOS::NetStack::Http {

constexpr const char *LRU_INDEX = "LRUIndex";
constexpr const int DECIMAL_BASE = 10;
constexpr const int MAX_SIZE = 1024 * 1024;
constexpr const size_t INVALID_SIZE = SIZE_MAX;
constexpr const int MAX_DISK_CACHE_SIZE = 1024 * 1024 * 10;
constexpr const int MIN_DISK_CACHE_SIZE = 1024 * 1024;

class LRUCache {
public:
    LRUCache();

    explicit LRUCache(size_t capacity);

    std::unordered_map<std::string, std::string> Get(const std::string &key);

    void Put(const std::string &key, const std::unordered_map<std::string, std::string> &value);

    void MergeOtherCache(const LRUCache &other);

    cJSON* WriteCacheToJsonValue();

    void ReadCacheFromJsonValue(const cJSON* root);

    void Clear();

private:
    struct Node {
        std::string key;
        std::unordered_map<std::string, std::string> value;

        Node() = delete;

        Node(std::string key, std::unordered_map<std::string, std::string> value);
    };

    void AddNode(const Node &node);

    void MoveNodeToHead(const std::list<Node>::iterator &it);

    void EraseTailNode();

    std::mutex mutex_;
    std::unordered_map<std::string, std::list<Node>::iterator> cache_;
    std::list<Node> nodeList_;
    size_t capacity_;
    size_t size_;
};

class DiskHandler final {
public:
    DiskHandler() = delete;

    explicit DiskHandler(std::string fileName);

    void Write(const std::string &str);

    void Delete();

    [[nodiscard]] std::string Read();

private:
    std::mutex mutex_;

    std::string fileName_;
};

class LRUCacheDiskHandler {
public:
    LRUCacheDiskHandler() = delete;

    LRUCacheDiskHandler(std::string fileName, size_t capacity);

    void WriteCacheToJsonFile();

    void ReadCacheFromJsonFile();

    void Delete();

    void SetCapacity(size_t capacity);

    std::unordered_map<std::string, std::string> Get(const std::string &key);

    void Put(const std::string &key, const std::unordered_map<std::string, std::string> &value);

private:
    LRUCache cache_;
    DiskHandler diskHandler_;
    std::atomic<size_t> capacity_;

    cJSON* ReadJsonValueFromFile();

    void WriteJsonValueToFile(const cJSON *root);
};

} // namespace OHOS::NetStack::Http
#endif /* LRU_CACHE_DISK_HANDLER_H */
