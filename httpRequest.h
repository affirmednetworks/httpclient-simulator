#ifndef _HttpRequest_h_
#define _HttpRequest_h_

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

#include "httpClientCommon.h"
#include <unistd.h>
#include <stdlib.h>
#include <exception>
#include <atomic>
#include <future>

extern int loglevel;

namespace base {
    class HttpCallBackIf;
}

using HttpResponseReadyCallbackSharedPtr = std::shared_ptr<base::HttpCallBackIf>;
using HttpResponseReadyCallbackWeakPtr = std::weak_ptr<base::HttpCallBackIf>;

namespace base 
{
    typedef enum
    {
        invalid_c=0,
        get_c=1,
        post_c=2,
        put_c=3,
        del_c=4,
        patch_c=5,
        head_c=6,
        trace_c=7,
        options_c=8,
        connect_c=9,
        maxtype_c
    }CniMsgType;

    enum TypeSocket {BlockingSocket, NonBlockingSocket};

    class HttpCookie
    {
        public:
            HttpCookie():transId_m(++cookie_m) {}
            ~HttpCookie(){}
            const HttpCookie& operator=(const HttpCookie& other)=delete;
            const uint32_t getId() const {
                return transId_m;
            }
        private:
            static std::atomic<uint32_t> cookie_m;
            uint32_t transId_m=0;
    };
    using HttpCookieShPtr = std::shared_ptr<base::HttpCookie>;

    class IpAddress
    {
        public:
            IpAddress(){}
            IpAddress(uint32_t ip):ip_m(ip) {}
            ~IpAddress(){}
            std::string toString() {
                in_addr inaddr;
                inaddr.s_addr = ip_m;
                return inet_ntoa(inaddr);
            }
            uint32_t getV4Address() { return ip_m;} 
        private:
            uint32_t ip_m;
    };

    class TcpSocket
    {
        public:
            TcpSocket() {sockfd_m=0;open_m=false;}
            TcpSocket(IpAddress& ipA):TcpSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, ipA.getV4Address()) {
            }
            TcpSocket(uint32_t domain, uint32_t type, uint32_t prot, uint32_t ipv4): open_m(false) {

                if (!this->open(domain, type, prot)) {
                    throw std::exception();
                }
                int32_t set = 1; 
                if (setsockopt(sockfd_m, SOL_SOCKET, SO_REUSEADDR, (char*)&set, sizeof(set)) == -1) {
                    throw std::exception();
                }

                uint16_t port = 0;
                struct sockaddr_storage __ss;
                struct sockaddr_in* localAddr;
                localAddr = (struct sockaddr_in*) &__ss;
                localAddr->sin_family = AF_INET;
                localAddr->sin_addr.s_addr = ipv4;
                localAddr->sin_port = htons(port);

                if (bind(sockfd_m, (struct sockaddr*)&__ss, sizeof(__ss)) < 0) {
                    // In order to meet the strong guarantee close the socket.
                    this->close();
                    throw std::exception();
                }

            }
            bool open(uint32_t domain, uint32_t type, uint32_t prot) {
                if (open_m) {
                    //do not open again so we do not overwrite fd
                    return true;
                }

                if ((sockfd_m = socket(domain, type, prot)) < 0) {
                    return false;
                }

                //Socket Options feilds
                blocking_m = BlockingSocket;

                //Socket is open
                open_m = true;

                return true;
            }

            bool close() {
                int32_t ret = 0;
                do {
                    ret = ::close(sockfd_m);
                }
                while (ret < 0 && errno == EINTR);

                if (ret < 0) {
                    return false;
                }

                //FD is closed
                sockfd_m = -1;
                open_m = false;

                return true;
            }

            ~TcpSocket(){}
            bool setNoDelay(int32_t noDelay) {
                int flag = noDelay;
                if (setsockopt(sockfd_m, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(int)) == -1)
                    return false;
                return true;
            }
            int32_t getSocketFd() {
                return sockfd_m;
            }
        private:
            int32_t sockfd_m;
            bool open_m;
            TypeSocket blocking_m;
    };

    enum class HttpTransferFlag
    {
        HTTP_11  = 0,
        HTTP2_PRIOR_KNOWLEDGE  = 1
    };

    enum class Http2StreamDependency
    {
        HTTP_STREAM_DEP_INVALID  = 0,
        HTTP_STREAM_DEP_NORMAL  = 1,
        HTTP_STREAM_DEP_EXCLUSIVE  = 2,
    };


    /**
      HttpRequest used to send HTTP request and received HTTP response.
      */
    class HttpRequest : public std::enable_shared_from_this<HttpRequest>
    {
        public:
            HttpRequest();
            virtual ~HttpRequest();
            void SetRequestHeaders(const std::unordered_map<std::string, std::string>& headers);
            void AddRequestHeaders(const std::unordered_map<std::string, std::string>& headers);
            void AddRequestHeader(const std::string& field, const std::string& value);
            const std::multimap<std::string, std::string>& GetResponseHeaders() const;
            void SetRequestTimeoutInSec(uint16_t time);
            void SetRequestTimeoutInMilliSec(unsigned long time);

            typedef std::function<
                bool(const std::shared_ptr<HttpRequest>& connection,
                        char* body,
                        std::size_t expected_length,
                        std::size_t& actual_length)
                > ReadBodyCallback;

            typedef std::function<
                bool(const std::shared_ptr<HttpRequest>& connection,
                        const char* header,
                        std::size_t length)
                > WriteHeaderCallback;

            typedef std::function<
                bool(const std::shared_ptr<HttpRequest>& connection,
                        const char* body,
                        std::size_t length)
                > WriteBodyCallback;

            enum class DebugDataType {
                Information,
                ReceivedHeader,
                SentHeader,
                ReceivedBody,
                SentBody,
                ReceivedSslData,
                SentSslData,
            };

            typedef std::function<
                void(const std::shared_ptr<HttpRequest>& connection,
                        DebugDataType data_type,
                        const char* data,
                        std::size_t size)
                > DebugCallback;

            typedef std::function<void(const std::shared_ptr<HttpRequest>& connection)> FinishedCallback;

            virtual void Start();
            void SetVerbose(bool verbose);
            void SetUrl(const std::string& url);
            void SetDnsResolveItems(const std::multimap<std::string, std::string>& resolve_items);
            void SetDnsCacheTimeOut(uint32_t secs);
            void SetRequestBody(const std::shared_ptr<std::string>& body) {
                if(body != nullptr)
                    requestBody_m = body;
            }
            std::shared_ptr<std::string> GetRequestBody() {
                return requestBody_m;
            }
            void SetReceiveBody(bool receive_body);
            void SetConnectTimeoutInMilliseconds(long milliseconds);
            void SetTimeoutInMilliseconds(long milliseconds);
            void SetReadBodyCallback(const ReadBodyCallback& callback) {
                readBodyCallback_m = callback;
            }
            void SetWriteHeaderCallback(const WriteHeaderCallback& callback) {
                writeHeaderCallback_m = callback;
            }
            void SetWriteBodyCallback(const WriteBodyCallback& callback) {
                writeBodyCallback_m = callback;
            }
            void SetDebugCallback(const DebugCallback& callback);
            void SetFinishedCallback(const FinishedCallback& callback) {
                finishedCallback_m = callback;
            }
            void SetAppResponseCallback(const HttpResponseReadyCallbackSharedPtr& callback = nullptr) {
                appResponseCallback_m = callback;
            }
            HttpResponseReadyCallbackWeakPtr GetAppResponseCallback() {
                return appResponseCallback_m;
            }
            CURLcode GetResult() const {
                return result_m;
            }
            long GetResponseCode() const;
            long GetResponseCode(CURLcode cc) const;

            const std::string& GetResponseHeader() const {
                return responseHeader_m;
            }

            void ResetResponseHeader() {
                responseHeader_m.clear();
            }    

            const std::string& GetResponseBody() const {
                return responseBody_m;
            }

            CURL* GetHandle() const {
                return handle_mp;
            }

            std::string& GetUrl() {
                return requestUrl_m;
            }

            void SetCookie(const std::shared_ptr<base::HttpCookie>& cookie) {
                cookie_m = cookie;
            }

            std::shared_ptr<base::HttpCookie> GetCookie() {
                return cookie_m;
            }

            virtual void SetHttpMethod(base::CniMsgType type);

            virtual base::CniMsgType GetHttpMethod() {
                return httpMethod_m;
            }

            void SetTcpKeepAlive(bool enabled=true, uint32_t keepAliveIdleTime=60, uint32_t keepAliveInterval=60);

            void SetPodIpV4(uint32_t ip) { podIpV4_m = ip; }
            void SetPodIpV4(std::string ipAdr) {
                unsigned char buf[sizeof(struct in6_addr)];
                int s = inet_pton(AF_INET, ipAdr.c_str(), buf);
                if (s <= 0) {
                    if (s == 0)
                        LOG_ERROR("Not in presentation format");
                    else
                        perror("inet_pton");
                    exit(EXIT_FAILURE);
                } 
                podIpV4_m = s;
            }

            void SetPostSize(long size);
            void SetUpLoadHttpBody(bool enabled);

            void SetHTTP2Transfer(base::HttpTransferFlag flag) {
                httpTransferFlag_m = flag;
            }

            void SetHTTP2Transfer() {
                curl_easy_setopt(GetHandle(), CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
                curl_easy_setopt(GetHandle(), CURLOPT_PIPEWAIT, 1L);
            }

            base::HttpTransferFlag GetHTTP2Transfer() {
                return httpTransferFlag_m; 
            }

            bool IsSetWriteBodyCallback() const {
                return (writeBodyCallback_m)?true:false;
            }

            const uint32_t getCookieId() {
                return GetCookie()->getId();
            }

            std::promise<int>& Promise() {return response_m;}

        private:
            void InitStart();

            void Finished(CURLcode result);

            void CheckAndSetUpHttpBodyUpload();

        protected:
            virtual void ResetResponseStates();
            virtual void ResetResponseStatesB();

        private:
            static size_t CurlReadBodyCallback(char* buffer, size_t size, size_t nitems, void* instream);

            static size_t CurlWriteHeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata);

            static size_t CurlWriteBodyCallback(char* ptr, size_t size, size_t nmemb, void* v);

            static int CurlDebugCallback(CURL* handle,
                    curl_infotype type,
                    char* data,
                    size_t size,
                    void* userptr);

            void SetInitialOptions();

            void SetSharedHandle(bool enable=true);

            void ReleaseDnsResolveItems();

            bool ReadBody(char* body, std::size_t expected_length, std::size_t& actual_length);

            bool WriteHeader(const char* header, std::size_t length);

            bool WriteBody(const char* body, std::size_t length);

            void Debug(DebugDataType data_type, const char* data, std::size_t size);

            const char* GetResultString() const { return errorBuff_m; }

            const char* GetEffectiveUrl() const;
        private:

            static curl_socket_t CurlOpenSocketCallback(void* clientp, curlsocktype socket_type, curl_sockaddr* address);

            static int CurlCloseSocketCallback(void* clientp, curl_socket_t socket);

            curl_socket_t OpenSocket(curlsocktype socket_type, curl_sockaddr* address);

            bool CloseSocket(curl_socket_t socket);

        private:
            CURL* handle_mp;
            bool isRunning_m;
            char errorBuff_m[CURL_ERROR_SIZE]{0};

            curl_slist* dnsResolveItems_mp;
            std::size_t requestBodyReadLength_m;
            ReadBodyCallback readBodyCallback_m;
            WriteHeaderCallback writeHeaderCallback_m;
            WriteBodyCallback writeBodyCallback_m;
            DebugCallback debugCallback_m;
            FinishedCallback finishedCallback_m;
            HttpResponseReadyCallbackWeakPtr appResponseCallback_m;
            CURLcode result_m;
            std::string responseHeader_m;
            std::string responseBody_m;
            std::string requestUrl_m;
            std::shared_ptr<base::HttpCookie> cookie_m;
            std::shared_ptr<std::string> requestBody_m;
            std::shared_ptr<base::TcpSocket> tcpsock_m{nullptr};
            uint32_t podIpV4_m{0};
            base::CniMsgType    httpMethod_m;
            base::HttpTransferFlag httpTransferFlag_m;

            friend class HttpClientManager;

        private:
            void ParseResponseHeaders() const;

            void ReleaseRequestHeaders();

        private:
            curl_slist* requestHeaders_mp;
            mutable bool hasParsedResponseHeaders_m;
            mutable std::multimap<std::string, std::string> responseHeaders_m;
            std::promise<int> response_m;
    };

    class HttpClientResponse
    {
        public:
            explicit HttpClientResponse(const uint32_t tid, long rc, std::string&& hdrs, std::shared_ptr<std::string> buffPtr):tid_m(tid),responseCode_m(rc),httpRspHdrs_m(hdrs),httpRspBufferPtr_m(buffPtr) {
            }
            ~HttpClientResponse() = default;

            const uint32_t getTid() {
                return tid_m;
            }
            std::string& getHttpRspHdrs() {
                return httpRspHdrs_m;
            }
            std::shared_ptr<std::string> getHttpRspBuffer() {
                return httpRspBufferPtr_m;
            }
            long getRespCode() {
                return responseCode_m;
            }

        private:
            uint32_t tid_m;
            long responseCode_m;
            std::string httpRspHdrs_m;
            std::shared_ptr<std::string> httpRspBufferPtr_m;
    };

    using HttpClientRspPtr = std::shared_ptr<HttpClientResponse>;

    class HttpCallBackIf
    {
        public:
            HttpCallBackIf() {};

            virtual ~HttpCallBackIf() {};

            virtual void operator()(const HttpClientRspPtr& httpResp, 
                    HttpClientStatusCode sc)
            {};

        private:
            HttpCallBackIf(const HttpCallBackIf &)=delete;
            const HttpCallBackIf& operator=(const HttpCallBackIf &)=delete;
    };

    template <typename T1>
        class HttpAsyncCallBack : public HttpCallBackIf
    {
        public:
            HttpAsyncCallBack(T1 *class_p,
                    void(T1::*method_p)( const HttpClientRspPtr& httpResp, 
                        HttpClientStatusCode sc))
                : class_mp(class_p), method_mp(method_p)
            {
                if ( (class_mp == 0) || (method_mp == 0) )
                {
                    throw std::exception();
                }
            };

            virtual ~HttpAsyncCallBack() {};

            virtual void operator()(const HttpClientRspPtr& httpResp, 
                    HttpClientStatusCode sc)
            {
                if ((class_mp != nullptr) && (method_mp != nullptr))
                {
                    (*class_mp.*method_mp)(std::move(httpResp), std::move(sc));
                }
                else
                {
                    throw std::exception();
                }
            };


        private:
            // Pointer to the type
            T1 *class_mp;

            // Pointer to the callback function.
            void (T1::*method_mp) (const HttpClientRspPtr& httpResp,
                    HttpClientStatusCode sc);

    };

}
#endif
