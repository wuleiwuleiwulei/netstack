/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_NETSTACK_LOG
#define COMMUNICATIONNETSTACK_NETSTACK_LOG

#include <cstring>
#include <string>

#define MAKE_FILE_NAME strrchr(__FILE__, '/') + 1

#if !defined(_WIN32) && !defined(__APPLE__)

#define LOG_DOMAIN 0xD0015B0

#define LOG_TAG "NETSTACK"

#include "hilog/log.h"

#define NETSTACK_HILOG_PRINT(Level, fmt, ...) \
    (void)HILOG_##Level(LOG_CORE, "[%{public}s:%{public}d] " fmt, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

#define NETSTACK_CORE_HILOG_PRINT(Level, fmt, ...) \
    (void)HILOG_##Level(LOG_CORE, fmt, ##__VA_ARGS__)

#else

#include "securec.h"
#include <cstdarg>
#include <cstdio>

static constexpr uint32_t NETSTACK_MAX_BUFFER_SIZE = 4096;

static void NetStackStripFormatString(const std::string &prefix, std::string &str)
{
    for (auto pos = str.find(prefix, 0); pos != std::string::npos; pos = str.find(prefix, pos)) {
        str.erase(pos, prefix.size());
    }
}

static void NetStackPrintLog(const char *fmt, ...)
{
    std::string newFmt(fmt);
    NetStackStripFormatString("{public}", newFmt);
    NetStackStripFormatString("{private}", newFmt);

    va_list args;
    va_start(args, fmt);

    char buf[NETSTACK_MAX_BUFFER_SIZE] = {0};
    int ret = vsnprintf_s(buf, sizeof(buf), sizeof(buf) - 1, newFmt.c_str(), args);
    if (ret < 0) {
        va_end(args);
        return;
    }
    va_end(args);

    printf("%s\r\n", buf);
    fflush(stdout);
}

#define NETSTACK_HILOG_PRINT(Level, fmt, ...) \
    NetStackPrintLog("NETSTACK %s [%s:%d] " fmt, #Level, MAKE_FILE_NAME, __LINE__, ##__VA_ARGS__)

#define NETSTACK_CORE_HILOG_PRINT(Level, fmt, ...) NetStackPrintLog("NETSTACK %s " fmt, #Level, ##__VA_ARGS__)

#endif /* !defined(_WIN32) && !defined(__APPLE__) */

#define NETSTACK_LOGE(fmt, ...) NETSTACK_HILOG_PRINT(ERROR, fmt, ##__VA_ARGS__)

#define NETSTACK_LOGI(fmt, ...) NETSTACK_HILOG_PRINT(INFO, fmt, ##__VA_ARGS__)

#define NETSTACK_LOGD(fmt, ...) NETSTACK_HILOG_PRINT(DEBUG, fmt, ##__VA_ARGS__)

#define NETSTACK_CORE_LOGI(fmt, ...) NETSTACK_CORE_HILOG_PRINT(INFO, fmt, ##__VA_ARGS__)

#endif /* COMMUNICATIONNETSTACK_NETSTACK_LOG */
