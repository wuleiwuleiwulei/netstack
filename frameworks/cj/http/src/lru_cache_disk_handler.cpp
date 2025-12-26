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

#include "lru_cache_disk_handler.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include "netstack_log.h"

namespace OHOS::NetStack::Http {

static size_t GetMapValueSize(const std::unordered_map<std::string, std::string> &m)
{
    size_t size = 0;
    for (const auto &p : m) {
        if (p.second.size() > MAX_SIZE) {
            return INVALID_SIZE;
        }
        if (size + p.second.size() > MAX_SIZE) {
            return INVALID_SIZE;
        }
        size += p.second.size();
    }
    if (size > MAX_SIZE || size == 0) {
        return INVALID_SIZE;
    }
    return size;
}

LRUCache::Node::Node(std::string key, std::unordered_map<std::string, std::string> value)
    : key(std::move(key)), value(std::move(value))
{
}

LRUCache::LRUCache() : capacity_(MAX_SIZE), size_(0) {}

LRUCache::LRUCache(size_t capacity) : capacity_(std::min<size_t>(MAX_SIZE, capacity)), size_(0) {}

void LRUCache::AddNode(const Node &node)
{
    nodeList_.emplace_front(node);
    cache_[node.key] = nodeList_.begin();
    size_ += GetMapValueSize(node.value);
}

void LRUCache::MoveNodeToHead(const std::list<Node>::iterator &it)
{
    std::string key = it->key;
    std::unordered_map<std::string, std::string> value = it->value;
    nodeList_.erase(it);
    nodeList_.emplace_front(key, value);
    cache_[key] = nodeList_.begin();
}

void LRUCache::EraseTailNode()
{
    if (nodeList_.empty()) {
        return;
    }
    Node node = nodeList_.back();
    nodeList_.pop_back();
    cache_.erase(node.key);
    size_ -= GetMapValueSize(node.value);
}

std::unordered_map<std::string, std::string> LRUCache::Get(const std::string &key)
{
    std::lock_guard<std::mutex> guard(mutex_);

    if (cache_.find(key) == cache_.end()) {
        return {};
    }
    auto it = cache_[key];
    auto value = it->value;
    MoveNodeToHead(it);
    return value;
}

void LRUCache::Put(const std::string &key, const std::unordered_map<std::string, std::string> &value)
{
    std::lock_guard<std::mutex> guard(mutex_);

    if (GetMapValueSize(value) == INVALID_SIZE) {
        NETSTACK_LOGE("value is invalid(0 or too long) can not insert to cache");
        return;
    }

    if (cache_.find(key) == cache_.end()) {
        AddNode(Node(key, value));
        while (size_ > capacity_) {
            EraseTailNode();
        }
        return;
    }

    auto it = cache_[key];

    size_ -= GetMapValueSize(it->value);
    it->value = value;
    size_ += GetMapValueSize(it->value);

    MoveNodeToHead(it);
    while (size_ > capacity_) {
        EraseTailNode();
    }
}

void LRUCache::MergeOtherCache(const LRUCache &other)
{
    std::list<Node> reverseList;
    {
        // set mutex in min scope
        std::lock_guard<std::mutex> guard(mutex_);
        if (other.nodeList_.empty()) {
            return;
        }
        reverseList = other.nodeList_;
    }
    reverseList.reverse();
    for (const auto &node : reverseList) {
        Put(node.key, node.value);
    }
}

cJSON* LRUCache::WriteCacheToJsonValue()
{
    cJSON* root = cJSON_CreateObject();

    int index = 0;
    {
        // set mutex in min scope
        std::lock_guard<std::mutex> guard(mutex_);
        for (const auto &node : nodeList_) {
            cJSON *nodeKey = cJSON_CreateObject();
            for (const auto &p : node.value) {
                cJSON_AddItemToObject(nodeKey, p.first.c_str(), cJSON_CreateString(p.second.c_str()));
            }
            cJSON_AddItemToObject(nodeKey, LRU_INDEX, cJSON_CreateString(std::to_string(index).c_str()));
            ++index;
            cJSON_AddItemToObject(root, node.key.c_str(), nodeKey);
        }
    }
    return root;
}

void LRUCache::ReadCacheFromJsonValue(const cJSON* root)
{
    std::vector<Node> nodeVec;
    for (int32_t i = 0; i < cJSON_GetArraySize(root); i++) {
        cJSON *keyItem = cJSON_GetArrayItem(root, i);
        if (keyItem == nullptr || !cJSON_IsObject(keyItem)) {
            continue;
        }
        std::string key = keyItem->string;
        std::unordered_map<std::string, std::string> m;
        for (int32_t j = 0; j < cJSON_GetArraySize(keyItem); j++) {
            cJSON *valueItem = cJSON_GetArrayItem(keyItem, j);
            if (valueItem == nullptr) {
                NETSTACK_LOGD("valueItem is null");
                continue;
            }
            std::string valueKey = valueItem->string;
            m[valueKey] = cJSON_GetStringValue(valueItem);
        }

        if (m.find(LRU_INDEX) != m.end()) {
            nodeVec.emplace_back(key, m);
        }
    }
    std::sort(nodeVec.begin(), nodeVec.end(), [](Node &a, Node &b) {
        return std::strtol(a.value[LRU_INDEX].c_str(), nullptr, DECIMAL_BASE) >
               std::strtol(b.value[LRU_INDEX].c_str(), nullptr, DECIMAL_BASE);
    });
    for (auto &node : nodeVec) {
        node.value.erase(LRU_INDEX);
        if (!node.value.empty()) {
            Put(node.key, node.value);
        }
    }
}
void LRUCache::Clear()
{
    std::lock_guard<std::mutex> guard(mutex_);
    cache_.clear();
    nodeList_.clear();
}

DiskHandler::DiskHandler(std::string fileName) : fileName_(std::move(fileName)) {}

void DiskHandler::Write(const std::string &str)
{
    std::lock_guard<std::mutex> guard(mutex_);
    std::ofstream w(fileName_);
    if (!w.is_open()) {
        return;
    }
    w << str;
    w.close();
}

std::string DiskHandler::Read()
{
    std::lock_guard<std::mutex> guard(mutex_);
    std::ifstream r(fileName_);
    if (!r.is_open()) {
        return {};
    }
    std::stringstream b;
    b << r.rdbuf();
    r.close();
    return b.str();
}

void DiskHandler::Delete()
{
    std::lock_guard<std::mutex> guard(mutex_);
    if (remove(fileName_.c_str()) < 0) {
        NETSTACK_LOGI("remove file error %{public}d", errno);
    }
}

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
