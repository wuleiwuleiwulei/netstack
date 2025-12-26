/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "netstack_hash_map.h"
#include "net_http_inner_types.h"
#include "netstack_log.h"

#define NETSTACK_HASH_FACTOR 31

static uint32_t Netstack_Hash(const char *key, uint32_t capacity)
{
    uint32_t hash = 0;
    for (uint32_t i = 0; i < strlen(key); i++) {
        hash = NETSTACK_HASH_FACTOR * hash + key[i];
    }
    return hash % capacity;
}

Netstack_HashMap *CreateMap(void)
{
    Netstack_HashMap *map = (Netstack_HashMap *)malloc(sizeof(Netstack_HashMap));
    if (map == nullptr) {
        NETSTACK_LOGE("failed to alloc memory for map");
        return nullptr;
    }
    map->capacity = DEFAULT_MAP_CAPACITY;
    map->size = 0;
    map->entries = (Netstack_HashMapEntry **)calloc(map->capacity, sizeof(Netstack_HashMapEntry *));
    if (map->entries == nullptr) {
        NETSTACK_LOGE("failed to alloc memory for map entries");
        free(map);
        return nullptr;
    }

    return map;
}

static uint32_t Netstack_RehashEntry(Netstack_HashMapEntry *currentPtr,
    uint32_t newCapacity, Netstack_HashMapEntry **newEntries)
{
    uint32_t size = 0;
    Netstack_HashMapEntry *nextPtr;
    do {
        nextPtr = currentPtr->next;
        uint32_t newHash = Netstack_Hash(currentPtr->key, newCapacity);
        if (newEntries[newHash] == nullptr) {
            newEntries[newHash] = currentPtr;
            newEntries[newHash]->next = nullptr;
            size++;
        } else {
            currentPtr->next = newEntries[newHash]->next;
            newEntries[newHash]->next = currentPtr;
        }
        currentPtr = nextPtr;
    } while (currentPtr != nullptr);
    return size;
}

static bool NetstackInvalidMap(Netstack_HashMap *map)
{
    return map == nullptr || map->entries == nullptr || map->capacity < DEFAULT_MAP_CAPACITY ||
           map->capacity > MAX_MAP_CAPACITY;
}

static uint32_t NetstackResizeMap(Netstack_HashMap *map)
{
    if (map->capacity >= MAX_MAP_CAPACITY) {
        NETSTACK_LOGE("map capacity reaches max, skip resize");
        return OH_HTTP_PARAMETER_ERROR;
    }
    uint32_t newCapacity = map->capacity * 2;
    Netstack_HashMapEntry **newEntries = (Netstack_HashMapEntry **)calloc(newCapacity, sizeof(Netstack_HashMapEntry *));
    if (newEntries == nullptr) {
        NETSTACK_LOGE("failed to insert map: no memory for resize");
        return OH_HTTP_OUT_OF_MEMORY;
    }

    map->size = 0;
    for (uint32_t i = 0; i < map->capacity; i++) {
        if (map->entries[i] != nullptr && map->entries[i]->key != nullptr) {
            map->size += Netstack_RehashEntry(map->entries[i], newCapacity, newEntries);
        }
    }

    NETSTACK_LOGI("success to resize map from %{public}u to %{public}u", map->capacity, newCapacity);
    free(map->entries);
    map->entries = newEntries;
    map->capacity = newCapacity;

    return OH_HTTP_RESULT_OK;
}

uint32_t Netstack_PutMapEntry(Netstack_HashMap *map, const char *key, void *value)
{
    if (NetstackInvalidMap(map) || key == nullptr) {
        return OH_HTTP_PARAMETER_ERROR;
    }

    if (map->size >= map->capacity) {
        (void)NetstackResizeMap(map);
    }

    uint32_t idx = Netstack_Hash(key, map->capacity);
    // set first entry
    if (map->entries[idx] == nullptr) {
        Netstack_HashMapEntry *entry = (Netstack_HashMapEntry *)malloc(sizeof(Netstack_HashMapEntry));
        if (entry == nullptr) {
            NETSTACK_LOGE("failed to alloc map entry");
            return OH_HTTP_OUT_OF_MEMORY;
        }
        entry->key = strdup(key);
        if (entry->key == nullptr) {
            free(entry);
            return OH_HTTP_OUT_OF_MEMORY;
        }
        entry->value = value;
        entry->next = nullptr;
        map->entries[idx] = entry;
        map->size++;
        return OH_HTTP_RESULT_OK;
    }

    Netstack_HashMapEntry *ptr = map->entries[idx];
    while (ptr != nullptr) {
        // replace exist entry
        if (strcmp(ptr->key, key) == 0) {
            ptr->value = value;
            return OH_HTTP_RESULT_OK;
        }
        ptr = ptr->next;
    }

    // insert after first entry
    Netstack_HashMapEntry *entry = (Netstack_HashMapEntry *)malloc(sizeof(Netstack_HashMapEntry));
    if (entry == nullptr) {
        return OH_HTTP_OUT_OF_MEMORY;
    }
    entry->key = strdup(key);
    if (entry->key == nullptr) {
        free(entry);
        return OH_HTTP_OUT_OF_MEMORY;
    }
    entry->value = value;
    entry->next = map->entries[idx]->next;
    map->entries[idx]->next = entry;

    return OH_HTTP_RESULT_OK;
}

void *Netstack_GetMapEntry(Netstack_HashMap *map, const char *key)
{
    if (NetstackInvalidMap(map) || key == nullptr) {
        return nullptr;
    }

    uint32_t idx = Netstack_Hash(key, map->capacity);
    Netstack_HashMapEntry *entry = map->entries[idx];
    while (entry != nullptr) {
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return nullptr;
}

uint32_t Netstack_DeleteMapEntry(Netstack_HashMap *map, const char *key)
{
    if (NetstackInvalidMap(map) || key == nullptr) {
        return OH_HTTP_PARAMETER_ERROR;
    }

    uint32_t idx = Netstack_Hash(key, map->capacity);
    if (map->entries[idx] == nullptr) {
        return OH_HTTP_RESULT_OK;
    }

    if (strcmp(map->entries[idx]->key, key) == 0) {
        Netstack_HashMapEntry *entry = map->entries[idx];
        map->entries[idx] = map->entries[idx]->next;
        free(entry->key);
        free(entry);
        if (map->entries[idx] == nullptr) {
            map->size--;
        }
        return OH_HTTP_RESULT_OK;
    }

    Netstack_HashMapEntry *prev = map->entries[idx];
    Netstack_HashMapEntry *entry = map->entries[idx]->next;
    while (entry != nullptr) {
        if (strcmp(entry->key, key) == 0) {
            prev->next = entry->next;
            free(entry->key);
            free(entry);
            return OH_HTTP_RESULT_OK;
        }
        prev = entry;
        entry = entry->next;
    }
    return OH_HTTP_RESULT_OK;
}

void Netstack_DestroyMapWithValue(Netstack_HashMap *map, Netstack_DestroyValueFunction destroyFunction)
{
    if (NetstackInvalidMap(map)) {
        return;
    }
    Netstack_HashMapEntry *entry;
    Netstack_HashMapEntry *next;
    for (uint32_t i = 0; i < map->capacity; i++) {
        entry = map->entries[i];
        while (entry != nullptr) {
            next = entry->next;
            entry->next = nullptr;
            free(entry->key);
            entry->key = nullptr;
            if (destroyFunction != nullptr) {
                destroyFunction(entry->value);
                entry->value = nullptr;
            }
            free(entry);
            map->entries[i] = nullptr;
            entry = next;
        }
    }
    free(map->entries);
    map->entries = nullptr;
    free(map);
}

void Netstack_DestroyMap(Netstack_HashMap *map)
{
    Netstack_DestroyMapWithValue(map, nullptr);
}

Netstack_MapIterator *Netstack_CreateMapIterator(Netstack_HashMap *map)
{
    if (NetstackInvalidMap(map)) {
        NETSTACK_LOGE("create map iterator failed: invalid map");
        return nullptr;
    }
    Netstack_MapIterator *iterator = (Netstack_MapIterator *)malloc(sizeof(Netstack_MapIterator));
    if (iterator == nullptr) {
        NETSTACK_LOGE("failed to alloc memory for map iterator");
        return nullptr;
    }
    iterator->map = map;
    for (uint32_t i = 0; i < map->capacity; i++) {
        if (map->entries[i] != nullptr) {
            iterator->currentIdx = i;
            iterator->currentEntry = map->entries[i];
            return iterator;
        }
    }
    NETSTACK_LOGI("map is empty, skip create map iterator");
    free(iterator);
    return nullptr;
}

void Netstack_MapIterateNext(Netstack_MapIterator *iterator)
{
    if (iterator == nullptr || iterator->currentEntry == nullptr || NetstackInvalidMap(iterator->map) ||
        iterator->currentIdx >= iterator->map->capacity) {
        return;
    }

    if (iterator->currentEntry->next != nullptr) {
        iterator->currentEntry = iterator->currentEntry->next;
        return;
    }

   for (uint32_t i = iterator->currentIdx + 1; i < iterator->map->capacity; i++) {
        if (iterator->map->entries[i] != nullptr) {
            iterator->currentEntry = iterator->map->entries[i];
            iterator->currentIdx = i;
            return;
        }
    }

    iterator->currentEntry = nullptr;
    iterator->currentIdx = iterator->map->capacity;
}

void Netstack_DestroyMapIterator(Netstack_MapIterator *iterator)
{
    free(iterator);
}