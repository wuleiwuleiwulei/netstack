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

#ifndef NETSTACK_HASH_MAP_C_H
#define NETSTACK_HASH_MAP_C_H

#include <cstdint>
#include <cstdio>
#include <string>
#include <cstdlib>

#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_MAP_CAPACITY 16
#define MAX_MAP_CAPACITY 16384

typedef struct Netstack_HashMapEntry {
   char *key;
   void *value;
   struct Netstack_HashMapEntry *next;
} Netstack_HashMapEntry;

typedef struct Netstack_HashMap {
   Netstack_HashMapEntry **entries;
   uint32_t size;
   uint32_t capacity;
} Netstack_HashMap;

typedef struct Netstack_MapIterator {
  Netstack_HashMap *map;
  uint32_t currentIdx;
  Netstack_HashMapEntry *currentEntry;
} Netstack_MapIterator;

typedef void (*Netstack_DestroyValueFunction)(void *value);

Netstack_HashMap *CreateMap(void);
uint32_t Netstack_PutMapEntry(Netstack_HashMap *map, const char *key, void *value);
void *Netstack_GetMapEntry(Netstack_HashMap *map, const char *key);
uint32_t Netstack_DeleteMapEntry(Netstack_HashMap *map, const char *key);
void Netstack_DestroyMap(Netstack_HashMap *map);
void Netstack_DestroyMapWithValue(Netstack_HashMap *map, Netstack_DestroyValueFunction destroyFunction);

Netstack_MapIterator *Netstack_CreateMapIterator(Netstack_HashMap *map);
void Netstack_MapIterateNext(Netstack_MapIterator *iterator);
void Netstack_DestroyMapIterator(Netstack_MapIterator *iterator);

#ifdef __cplusplus
}
#endif

#endif