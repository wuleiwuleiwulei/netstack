/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef COMMUNICATIONNETSTACK_CONSTANT_H
#define COMMUNICATIONNETSTACK_CONSTANT_H

#include <map>

namespace OHOS::NetStack::Socket {
static constexpr const size_t MAX_ERR_NUM = 256;

enum SocketErrorCode {
    SOCKET_ERROR_CODE_BASE = 2301000,
    SOCKET_SERVER_ERROR_CODE_BASE = 2303100,
};

#if defined(IOS_PLATFORM)
enum OHOSErrorCode {
    OHOS_ERR_UNDEFINED = -1,
    OHOS_ERR_EPERM = 1,
    OHOS_ERR_ENOENT = 2,
    OHOS_ERR_ESRCH = 3,
    OHOS_ERR_EINTR = 4,
    OHOS_ERR_EIO = 5,
    OHOS_ERR_ENXIO = 6,
    OHOS_ERR_E2BIG = 7,
    OHOS_ERR_ENOEXEC = 8,
    OHOS_ERR_EBADF = 9,
    OHOS_ERR_ECHILD = 10,
    OHOS_ERR_EAGAIN = 11,
    OHOS_ERR_ENOMEM = 12,
    OHOS_ERR_EACCES = 13,
    OHOS_ERR_EFAULT = 14,
    OHOS_ERR_ENOTBLK = 15,
    OHOS_ERR_EBUSY = 16,
    OHOS_ERR_EEXIST = 17,
    OHOS_ERR_EXDEV = 18,
    OHOS_ERR_ENODEV = 19,
    OHOS_ERR_ENOTDIR = 20,
    OHOS_ERR_EISDIR = 21,
    OHOS_ERR_EINVAL = 22,
    OHOS_ERR_ENFILE = 23,
    OHOS_ERR_EMFILE = 24,
    OHOS_ERR_ENOTTY = 25,
    OHOS_ERR_ETXTBSY = 26,
    OHOS_ERR_EFBIG = 27,
    OHOS_ERR_ENOSPC = 28,
    OHOS_ERR_ESPIPE = 29,
    OHOS_ERR_EROFS = 30,
    OHOS_ERR_EMLINK = 31,
    OHOS_ERR_EPIPE = 32,
    OHOS_ERR_EDOM = 33,
    OHOS_ERR_ERANGE = 34,
    OHOS_ERR_EDEADLK = 35,
    OHOS_ERR_ENAMETOOLONG = 36,
    OHOS_ERR_ENOLCK = 37,
    OHOS_ERR_ENOSYS = 38,
    OHOS_ERR_ENOTEMPTY = 39,
    OHOS_ERR_ELOOP = 40,
    OHOS_ERR_ENOMSG = 42,
    OHOS_ERR_EIDRM = 43,
    OHOS_ERR_EBADE = 52,
    OHOS_ERR_EBADR = 53,
    OHOS_ERR_ENOSTR = 60,
    OHOS_ERR_ENODATA = 61,
    OHOS_ERR_ETIME = 62,
    OHOS_ERR_ENOSR = 63,
    OHOS_ERR_EREMOTE = 66,
    OHOS_ERR_ENOLINK = 67,
    OHOS_ERR_EPROTO = 71,
    OHOS_ERR_EMULTIHOP = 72,
    OHOS_ERR_EBADMSG = 74,
    OHOS_ERR_EOVERFLOW = 75,
    OHOS_ERR_EILSEQ = 84,
    OHOS_ERR_EUSERS = 87,
    OHOS_ERR_ENOTSOCK = 88,
    OHOS_ERR_EDESTADDRREQ = 89,
    OHOS_ERR_EMSGSIZE = 90,
    OHOS_ERR_EPROTOTYPE = 91,
    OHOS_ERR_ENOPROTOOPT = 92,
    OHOS_ERR_EPROTONOSUPPORT = 93,
    OHOS_ERR_ESOCKTNOSUPPORT = 94,
    OHOS_ERR_EOPNOTSUPP = 95,
    OHOS_ERR_EPFNOSUPPORT = 96,
    OHOS_ERR_EAFNOSUPPORT = 97,
    OHOS_ERR_EADDRINUSE = 98,
    OHOS_ERR_EADDRNOTAVAIL = 99,
    OHOS_ERR_ENETDOWN = 100,
    OHOS_ERR_ENETUNREACH = 101,
    OHOS_ERR_ENETRESET = 102,
    OHOS_ERR_ECONNABORTED = 103,
    OHOS_ERR_ECONNRESET = 104,
    OHOS_ERR_ENOBUFS = 105,
    OHOS_ERR_EISCONN = 106,
    OHOS_ERR_ENOTCONN = 107,
    OHOS_ERR_ESHUTDOWN = 108,
    OHOS_ERR_ETOOMANYREFS = 109,
    OHOS_ERR_ETIMEDOUT = 110,
    OHOS_ERR_ECONNREFUSED = 111,
    OHOS_ERR_EHOSTDOWN = 112,
    OHOS_ERR_EHOSTUNREACH = 113,
    OHOS_ERR_EALREADY = 114,
    OHOS_ERR_EINPROGRESS = 115,
    OHOS_ERR_ESTALE = 116,
    OHOS_ERR_EDQUOT = 122,
    OHOS_ERR_ECANCELED = 125,
    OHOS_ERR_EOWNERDEAD = 130,
    OHOS_ERR_ENOTRECOVERABLE = 131,
    OHOS_ERR_EWOULDBLOCK = EAGAIN
};

static const std::map<int32_t, std::pair<OHOSErrorCode, std::string>> errCodeMap = {
    {EPERM, {OHOSErrorCode::OHOS_ERR_EPERM, "Operation not permitted"}},
    {ENOENT, {OHOSErrorCode::OHOS_ERR_ENOENT, "No such file or directory"}},
    {ESRCH, {OHOSErrorCode::OHOS_ERR_ESRCH, "No such process"}},
    {EINTR, {OHOSErrorCode::OHOS_ERR_EINTR, "Interrupted system call"}},
    {EIO, {OHOSErrorCode::OHOS_ERR_EIO, "Input/output error"}},
    {ENXIO, {OHOSErrorCode::OHOS_ERR_ENXIO, "No such device or address"}},
    {E2BIG, {OHOSErrorCode::OHOS_ERR_E2BIG, "Argument list too long"}},
    {ENOEXEC, {OHOSErrorCode::OHOS_ERR_ENOEXEC, "Exec format error"}},
    {EBADF, {OHOSErrorCode::OHOS_ERR_EBADF, "Bad file descriptor"}},
    {ECHILD, {OHOSErrorCode::OHOS_ERR_ECHILD, "No child processes"}},
    {EDEADLK, {OHOSErrorCode::OHOS_ERR_EDEADLK, "Resource deadlock avoided"}},
    {ENOMEM, {OHOSErrorCode::OHOS_ERR_ENOMEM, "Cannot allocate memory"}},
    {EACCES, {OHOSErrorCode::OHOS_ERR_EACCES, "Permission denied"}},
    {EFAULT, {OHOSErrorCode::OHOS_ERR_EFAULT, "Bad address"}},
    {ENOTBLK, {OHOSErrorCode::OHOS_ERR_ENOTBLK, "Block device required"}},
    {EBUSY, {OHOSErrorCode::OHOS_ERR_EBUSY, "Device or resource busy"}},
    {EEXIST, {OHOSErrorCode::OHOS_ERR_EEXIST, "File exists"}},
    {EXDEV, {OHOSErrorCode::OHOS_ERR_EXDEV, "Invalid cross-device link"}},
    {ENODEV, {OHOSErrorCode::OHOS_ERR_ENODEV, "No such device"}},
    {ENOTDIR, {OHOSErrorCode::OHOS_ERR_ENOTDIR, "Not a directory"}},
    {EISDIR, {OHOSErrorCode::OHOS_ERR_EISDIR, "Is a directory"}},
    {EINVAL, {OHOSErrorCode::OHOS_ERR_EINVAL, "Invalid argument"}},
    {ENFILE, {OHOSErrorCode::OHOS_ERR_ENFILE, "Too many open files in system"}},
    {EMFILE, {OHOSErrorCode::OHOS_ERR_EMFILE, "Too many open files"}},
    {ENOTTY, {OHOSErrorCode::OHOS_ERR_ENOTTY, "Inappropriate ioctl for device"}},
    {ETXTBSY, {OHOSErrorCode::OHOS_ERR_ETXTBSY, "Text file busy"}},
    {EFBIG, {OHOSErrorCode::OHOS_ERR_EFBIG, "File too large"}},
    {ENOSPC, {OHOSErrorCode::OHOS_ERR_ENOSPC, "No space left on device"}},
    {ESPIPE, {OHOSErrorCode::OHOS_ERR_ESPIPE, "Illegal seek"}},
    {EROFS, {OHOSErrorCode::OHOS_ERR_EROFS, "Read-only file system"}},
    {EMLINK, {OHOSErrorCode::OHOS_ERR_EMLINK, "Too many links"}},
    {EPIPE, {OHOSErrorCode::OHOS_ERR_EPIPE, "Broken pipe"}},
    {EDOM, {OHOSErrorCode::OHOS_ERR_EDOM, "Numerical argument out of domain"}},
    {ERANGE, {OHOSErrorCode::OHOS_ERR_ERANGE, "Numerical result out of range"}},
    {EAGAIN, {OHOSErrorCode::OHOS_ERR_EAGAIN, "Resource temporarily unavailable"}},
    {EWOULDBLOCK, {OHOSErrorCode::OHOS_ERR_EWOULDBLOCK, "Operation would block"}},
    {EINPROGRESS, {OHOSErrorCode::OHOS_ERR_EINPROGRESS, "Operation now in progress"}},
    {EALREADY, {OHOSErrorCode::OHOS_ERR_EALREADY, "Operation already in progress"}},
    {ENOTSOCK, {OHOSErrorCode::OHOS_ERR_ENOTSOCK, "Socket operation on non-socket"}},
    {EDESTADDRREQ, {OHOSErrorCode::OHOS_ERR_EDESTADDRREQ, "Destination address required"}},
    {EMSGSIZE, {OHOSErrorCode::OHOS_ERR_EMSGSIZE, "Message too long"}},
    {EPROTOTYPE, {OHOSErrorCode::OHOS_ERR_EPROTOTYPE, "Protocol wrong type for socket"}},
    {ENOPROTOOPT, {OHOSErrorCode::OHOS_ERR_ENOPROTOOPT, "Protocol not available"}},
    {EPROTONOSUPPORT, {OHOSErrorCode::OHOS_ERR_EPROTONOSUPPORT, "Protocol not supported"}},
    {ESOCKTNOSUPPORT, {OHOSErrorCode::OHOS_ERR_ESOCKTNOSUPPORT, "Socket type not supported"}},
    {ENOTSUP, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EOPNOTSUPP, {OHOSErrorCode::OHOS_ERR_EOPNOTSUPP, "Operation not supported"}},
    {EPFNOSUPPORT, {OHOSErrorCode::OHOS_ERR_EPFNOSUPPORT, "Protocol family not supported"}},
    {EAFNOSUPPORT, {OHOSErrorCode::OHOS_ERR_EAFNOSUPPORT, "Address family not supported by protocol"}},
    {EADDRINUSE, {OHOSErrorCode::OHOS_ERR_EADDRINUSE, "Address already in use"}},
    {EADDRNOTAVAIL, {OHOSErrorCode::OHOS_ERR_EADDRNOTAVAIL, "Cannot assign requested address"}},
    {ENETDOWN, {OHOSErrorCode::OHOS_ERR_ENETDOWN, "Network is down"}},
    {ENETUNREACH, {OHOSErrorCode::OHOS_ERR_ENETUNREACH, "Network is unreachable"}},
    {ENETRESET, {OHOSErrorCode::OHOS_ERR_ENETRESET, "Network dropped connection on reset"}},
    {ECONNABORTED, {OHOSErrorCode::OHOS_ERR_ECONNABORTED, "Software caused connection abort"}},
    {ECONNRESET, {OHOSErrorCode::OHOS_ERR_ECONNRESET, "Connection reset by peer"}},
    {ENOBUFS, {OHOSErrorCode::OHOS_ERR_ENOBUFS, "No buffer space available"}},
    {EISCONN, {OHOSErrorCode::OHOS_ERR_EISCONN, "Transport endpoint is already connected"}},
    {ENOTCONN, {OHOSErrorCode::OHOS_ERR_ENOTCONN, "Transport endpoint is not connected"}},
    {ESHUTDOWN, {OHOSErrorCode::OHOS_ERR_ESHUTDOWN, "Cannot send after transport endpoint shutdown"}},
    {ETOOMANYREFS, {OHOSErrorCode::OHOS_ERR_ETOOMANYREFS, "Too many references: cannot splice"}},
    {ETIMEDOUT, {OHOSErrorCode::OHOS_ERR_ETIMEDOUT, "Connection timed out"}},
    {ECONNREFUSED, {OHOSErrorCode::OHOS_ERR_ECONNREFUSED, "Connection refused"}},
    {ELOOP, {OHOSErrorCode::OHOS_ERR_ELOOP, "Too many levels of symbolic links"}},
    {ENAMETOOLONG, {OHOSErrorCode::OHOS_ERR_ENAMETOOLONG, "File name too long"}},
    {EHOSTDOWN, {OHOSErrorCode::OHOS_ERR_EHOSTDOWN, "Host is down"}},
    {EHOSTUNREACH, {OHOSErrorCode::OHOS_ERR_EHOSTUNREACH, "No route to host"}},
    {ENOTEMPTY, {OHOSErrorCode::OHOS_ERR_ENOTEMPTY, "Directory not empty"}},
    {EPROCLIM, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EUSERS, {OHOSErrorCode::OHOS_ERR_EUSERS, "Too many users"}},
    {EDQUOT, {OHOSErrorCode::OHOS_ERR_EDQUOT, "Disk quota exceeded"}},
    {ESTALE, {OHOSErrorCode::OHOS_ERR_ESTALE, "Stale NFS file handle"}},
    {EREMOTE, {OHOSErrorCode::OHOS_ERR_EREMOTE, "Object is remote"}},
    {EBADRPC, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {ERPCMISMATCH, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EPROGUNAVAIL, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EPROGMISMATCH, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EPROCUNAVAIL, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {ENOLCK, {OHOSErrorCode::OHOS_ERR_ENOLCK, "No locks available"}},
    {ENOSYS, {OHOSErrorCode::OHOS_ERR_ENOSYS, "Function not implemented"}},
    {EFTYPE, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EAUTH, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {ENEEDAUTH, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EPWROFF, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EDEVERR, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EOVERFLOW, {OHOSErrorCode::OHOS_ERR_EOVERFLOW, "Value too large for defined data type"}},
    {EBADEXEC, {OHOSErrorCode::OHOS_ERR_EBADE, "Invalid exchange"}},
    {EBADARCH, {OHOSErrorCode::OHOS_ERR_EBADR, "Invalid request descriptor"}},
    {ESHLIBVERS, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EBADMACHO, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {ECANCELED, {OHOSErrorCode::OHOS_ERR_ECANCELED, "Operation Canceled"}},
    {EIDRM, {OHOSErrorCode::OHOS_ERR_EIDRM, "Identifier removed"}},
    {ENOMSG, {OHOSErrorCode::OHOS_ERR_ENOMSG, "No message of desired type"}},
    {EILSEQ, {OHOSErrorCode::OHOS_ERR_EILSEQ, "Invalid or incomplete multibyte or wide character"}},
    {ENOATTR, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {EBADMSG, {OHOSErrorCode::OHOS_ERR_EBADMSG, "Bad message"}},
    {EMULTIHOP, {OHOSErrorCode::OHOS_ERR_EMULTIHOP, "Multihop attempted"}},
    {ENODATA, {OHOSErrorCode::OHOS_ERR_ENODATA, "No data available"}},
    {ENOLINK, {OHOSErrorCode::OHOS_ERR_ENOLINK, "Link has been severed"}},
    {ENOSR, {OHOSErrorCode::OHOS_ERR_ENOSR, "Out of streams resources"}},
    {ENOSTR, {OHOSErrorCode::OHOS_ERR_ENOSTR, "Device not a stream"}},
    {EPROTO, {OHOSErrorCode::OHOS_ERR_EPROTO, "Protocol error"}},
    {ETIME, {OHOSErrorCode::OHOS_ERR_ETIME, "Timer expired"}},
    {EOPNOTSUPP, {OHOSErrorCode::OHOS_ERR_EOPNOTSUPP, "Operation not supported"}},
    {ENOPOLICY, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {ENOTRECOVERABLE, {OHOSErrorCode::OHOS_ERR_ENOTRECOVERABLE, "State not recoverable"}},
    {EOWNERDEAD, {OHOSErrorCode::OHOS_ERR_EOWNERDEAD, "Owner died"}},
    {EQFULL, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
    {ELAST, {OHOSErrorCode::OHOS_ERR_UNDEFINED, "Unknown Other Error"}},
};

class ErrCodePlatformAdapter {
public:
    static int32_t GetOHOSErrCode(int32_t iosErrCode)
    {
        auto iter = errCodeMap.find(iosErrCode);
        if (iter != errCodeMap.end()) {
            return static_cast<int32_t>(iter->second.first);
        }
        return static_cast<int32_t>(OHOSErrorCode::OHOS_ERR_UNDEFINED);
    }

    static void GetOHOSErrMessage(int32_t iosErrCode, std::string &errMessage)
    {
        auto iter = errCodeMap.find(iosErrCode);
        if (iter != errCodeMap.end()) {
            errMessage = iter->second.second;
        } else {
            errMessage = "Unknown Other Error";
        }
    }
};
#endif
} // namespace OHOS::NetStack::Socket

#endif /* COMMUNICATIONNETSTACK_CONSTANT_H */
