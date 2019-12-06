#ifndef _httpClient_Common_
#define _httpClient_Common_

/*
The MIT License

Copyright (c) 2019 Kunal Ekawde

Permission is hereby granted, free of charge, 
to any person obtaining a copy of this software and 
associated documentation files (the "Software"), to 
deal in the Software without restriction, including 
without limitation the rights to use, copy, modify, 
merge, publish, distribute, sublicense, and/or sell 
copies of the Software, and to permit persons to whom 
the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice 
shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR 
ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, 
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <system_error>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <string>
#include <curl/curl.h>
#include <unordered_map>
#include <map>
#include <vector>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#define HTTP_CLIENT_URI_PROTO_SKIP_LEN 8
#define HTTP_CLIENT_MAX_CONNECTS 1000
#define HTTP_CLIENT_MAX_CONNECTS_PERHOST 100
#define HTTP_CLIENT_MAX_PARALLELCONNECTS 100
#define HTTP_DNS_CACHE_TIMEOUT_SECS 60
#define MHDHTTP_HEADER_COOKIE "cookie"
#define MHDHTTP_HEADER_COOKIELEN 6


enum class HttpClientStatusCode 
{
    HTTP_INVALID = 0,
    HTTP_SEND_FAILED = 1,  // Internal error by send API & not HTTP
    HTTP_SEND_SUCCESS = 2, // Internal success by send API & not HTTP
    HTTP_LIB_INTERNAL = 3, // Internal error from http lib wrapper to libcurl 
    HTTP_REQUEST_CANCEL_SUCCESS = 4,
    HTTP_REQUEST_CANCEL_FAILED = 5,
    HTTP_REQUEST_TIMEOUT = 460, // HTTP Txn timed out
    HTTP_EMPTY_REPLY_FROM_SERVER = 461, // when tcp goees down
    HTTP_COULD_NOT_RESOLVE_HOST = 462,
    HTTP_COULD_NOT_CONNECT = 463,
    HTTP_CHUNKED_REQUEST_FAILURE = 464,
    HTTP_TRANSPORT_ERROR = 465,
    HTTP_CLIENT_GENERIC_ERROR = 499 //last one
};

namespace base
{
    typedef uint32_t PollEvents;
    constexpr int NUM_LOCKS=CURL_LOCK_DATA_LAST;

    class HttpSharedHandle
    {
        public:
            typedef void (*lock_function_t)(CURL* handle, curl_lock_data data, curl_lock_access access, void* userptr);
            typedef void (*unlock_function_t)(CURL* handle, curl_lock_data data, void* userptr);

        private:
            // share
            CURLSH*            curlSharedHandle_m{nullptr};
            std::mutex         mutex_m[NUM_LOCKS];

            static void Lock(CURL* handle, curl_lock_data data, curl_lock_access access, void* userptr) {
                HttpSharedHandle* self = static_cast<HttpSharedHandle*>(userptr);
                self->mutex_m[data].lock();// cannot use std::lock_guard
            }

            static void Unlock(CURL* handle, curl_lock_data data, void* userptr) {
                HttpSharedHandle* self = static_cast<HttpSharedHandle*>(userptr);
                self->mutex_m[data].unlock();//cannot use std::lock_guard
            }

            HttpSharedHandle() {
                curlSharedHandle_m = curl_share_init();
                if (!curlSharedHandle_m) {
                    throw std::bad_alloc();
                }
                SetLockFunction(&HttpSharedHandle::Lock);
                SetUnlockFunction(&HttpSharedHandle::Unlock);
                SetUserData(this);
            }

            ~HttpSharedHandle() {
                if (curlSharedHandle_m) {
                    curl_share_cleanup(curlSharedHandle_m);
                    curlSharedHandle_m = nullptr;
                }
            }

        public:

            static HttpSharedHandle* getInstance() {
                static HttpSharedHandle s;
                return &s;
            }

            CURLSHcode SetUserData(void* user_data) {
                return curl_share_setopt(curlSharedHandle_m, CURLSHOPT_USERDATA, user_data);
            }

            CURLSHcode SetLockFunction(lock_function_t lock_function) {
                return curl_share_setopt(curlSharedHandle_m, CURLSHOPT_LOCKFUNC, lock_function);
            }

            CURLSHcode SetUnlockFunction(unlock_function_t unlock_function) {
                return curl_share_setopt(curlSharedHandle_m, CURLSHOPT_UNLOCKFUNC, unlock_function);
            }
            CURLSH* GetSharedNativeHandle() { return curlSharedHandle_m; }
            CURLSHcode  SetShareDns(bool enabled) {
                return curl_share_setopt(curlSharedHandle_m, enabled ? CURLSHOPT_SHARE : CURLSHOPT_UNSHARE, CURL_LOCK_DATA_DNS);
            }


    };
}

using namespace base;

inline const std::error_category& CurlMultiErrorCategory() {

    class CurlMultiErrorCategory : public std::error_category {
        public:
            const char* name() const noexcept override {
                return "CURLMcode";
            }

            std::string message(int condition) const override {
                return std::string(name());
            }
    };

    static CurlMultiErrorCategory category;
    return category;
}

inline const std::error_category& HttpLibErrorCategory() {

    class HttpLibErrorCategory : public std::error_category {
        public:
            const char* name() const noexcept override {
                return "HttpLibcode";
            }

            std::string message(int condition) const override {
                return std::string(name());
            }
    };

    static HttpLibErrorCategory category;
    return category;
}

#include <time.h>
static inline char *timenow();

#define _FILE strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__

#define NO_LOG          0x00
#define ERROR_LEVEL     0x01
#define INFO_LEVEL      0x02
#define DEBUG_LEVEL     0x03

extern int loglevel;
#define LOG_LEVEL   loglevel

#ifndef LOG_LEVEL
#define LOG_LEVEL   DEBUG_LEVEL
#endif
#define PRINTFUNCTION(format, ...)      fprintf(stderr, format, __VA_ARGS__)
#define LOG_FMT             "%s | %-7s | %-15s | %s:%d | "
#define LOG_ARGS(LOG_TAG)   timenow(), LOG_TAG, _FILE, __FUNCTION__, __LINE__

#define NEWLINE     "\n"

#define ERROR_TAG   "ERROR"
#define INFO_TAG    "INFO"
#define DEBUG_TAG   "DEBUG"


#define LOG_DEBUG(message, args...) do { if (loglevel>=DEBUG_LEVEL) \
                                           PRINTFUNCTION(LOG_FMT message NEWLINE, LOG_ARGS(DEBUG_TAG), ## args);\
                                         else\
                                           ;\
                                       }while(0)
#define LOG_INFO(message, args...) do { if (loglevel>=INFO_LEVEL) \
                                           PRINTFUNCTION(LOG_FMT message NEWLINE, LOG_ARGS(INFO_TAG), ## args);\
                                         else\
                                           ;\
                                       }while(0)
#define LOG_ERROR(message, args...) do { if (loglevel>=ERROR_LEVEL) \
                                           PRINTFUNCTION(LOG_FMT message NEWLINE, LOG_ARGS(ERROR_TAG), ## args);\
                                         else\
                                           ;\
                                       }while(0)

static inline char *timenow() {
    static char buffer[64];
    time_t rawtime;
    struct tm *timeinfo;
    
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    
    strftime(buffer, 64, "%Y-%m-%d %H:%M:%S", timeinfo);
    
    return buffer;
}

#endif
