#ifndef _httpClientManager_h_
#define _httpClientManager_h_

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

#include <map>
#include <memory>
#include <system_error>
#include <curl/curl.h>
#include <sys/epoll.h>
#include "httpRequest.h"

extern int loglevel;

namespace base {

    class HttpSocketWatcher;
    class HttpClientManager {
        public:
            explicit HttpClientManager(unsigned int maxConnects=0, unsigned int maxConnectsPerHost=0, 
                    unsigned int maxParallelConnects=0, unsigned int dnsCacheTimeOut=0);

            ~HttpClientManager();

            std::error_condition StartConnection(const std::shared_ptr<HttpRequest>& connection);

            std::error_condition AbortConnection(const std::shared_ptr<HttpRequest>& connection);

            CURLM* GetHandle() const {
                return multi_handle_m;
            }
            typedef std::function<void(curl_socket_t socket, bool can_write)> EventCallback;

            void httpClientResponseCb(const std::shared_ptr<HttpRequest> httprequest);

            void setEPFD(int fd) {epollFd_m = fd;}
            int EPFD() {return epollFd_m;}
            int TFD() {return tfd_m;}

            std::shared_ptr<HttpRequest> createRequest(std::string url, const std::unordered_map<std::string, std::string>& httpHeaders,
                    std::string buffer, base::HttpCookieShPtr cookie=nullptr,
                    const HttpResponseReadyCallbackSharedPtr& httpRspCb=nullptr, bool h2=true);

            void TimerTriggered();

            void SocketEventTriggered(curl_socket_t socket, base::PollEvents event);


        private:
            static curl_socket_t CurlOpenSocketCallback(void* clientp, curlsocktype socket_type, curl_sockaddr* address);

            static int CurlCloseSocketCallback(void* clientp, curl_socket_t socket);

            static int CurlTimerCallback(CURLM* multi_handle, long timeout_ms, void* user_pointer);

            static int CurlSocketCallback(CURL* easy_handle,
                    curl_socket_t socket,
                    int action,
                    void* user_pointer,
                    void* socket_pointer);

            curl_socket_t OpenSocket(curlsocktype socket_type, curl_sockaddr* address);
            bool CloseSocket(curl_socket_t socket);

            void WatchSocket(curl_socket_t socket, int action, void* socket_pointer);

            void CheckFinishedConnections();

            void SetTimer(unsigned long timeout_ms);
            void StartHttpTimer(unsigned long timeout_ms);
            void StopHttpTimer();

            curl_socket_t Open(curlsocktype socket_type, const curl_sockaddr* address) ;
            bool Close(curl_socket_t socket) ;
            void Watch(curl_socket_t socket, base::PollEvents event, const EventCallback& callback) ;
            void StopWatching(curl_socket_t socket) ;


        private:
            HttpClientManager(const HttpClientManager&) = delete;
            HttpClientManager& operator=(const HttpClientManager&) = delete;

        private:

            CURLM* multi_handle_m{nullptr};
            std::map<CURL*, std::shared_ptr<HttpRequest>> runningConnections_m;
            unsigned int  dnsCacheTimeOut_m{0};

            std::map<curl_socket_t, std::shared_ptr<base::TcpSocket>> socketsTable_m;
            std::map<curl_socket_t, std::shared_ptr<HttpSocketWatcher>> watchersTable_m;

            int  epollFd_m{0};
            int  tfd_m{0};

    };

    class HttpSocketWatcher 
    {
        public:
            HttpSocketWatcher(const std::shared_ptr<base::TcpSocket>& socket,
                    base::PollEvents event,
                    const HttpClientManager::EventCallback& callback,
                    int epfd): 
                socket_mp(socket),
                event_m(event),
                callback_m(callback),
                isStopped_m(false),
                epfd_m(epfd)
        {}

            ~HttpSocketWatcher() = default;

            void Start() {
                Watch();
            }

            void Stop() {
                isStopped_m = true;
                if (epoll_ctl(epfd_m, EPOLL_CTL_DEL, socket_mp->getSocketFd(), NULL) == -1) {
                    LOG_ERROR("EPOLL_CTL_DEL failed for fd: %d : %s",
                            socket_mp->getSocketFd(), strerror(errno));
                }
            }

            void UpdateWatch(base::PollEvents event) {
                event_m = event;
                struct epoll_event ev;
                memset(&ev, 0, sizeof(ev));
                ev.events = event_m;
                ev.data.fd = socket_mp->getSocketFd();

                if (epoll_ctl(epfd_m, EPOLL_CTL_MOD, socket_mp->getSocketFd(), &ev) == -1) {
                    LOG_ERROR("EPOLL_CTL_MOD failed for fd: %d : %s\n",
                            socket_mp->getSocketFd(), strerror(errno));
                }

                LOG_DEBUG("UpdateWatch: updated socket event to dispatcher"
                        "socket:%d", socket_mp->getSocketFd());
            }

        private:
            void Watch() {
                struct epoll_event ev;
                ev.events = EPOLLIN;
                ev.data.fd = socket_mp->getSocketFd();

                if(epoll_ctl(epfd_m, EPOLL_CTL_ADD, socket_mp->getSocketFd(), &ev))
                    LOG_ERROR("EPOLL_CTL_ADD failed for fd: %d : %s\n",
                            socket_mp->getSocketFd(), strerror(errno));
                LOG_DEBUG("Watch: Added socket to dispatcher socket:%d ", socket_mp->getSocketFd());
            }

            void EventTriggered(int32_t socket, base::PollEvents events ) {
                LOG_DEBUG("EventTriggered socket:%d", socket_mp->getSocketFd());
                callback_m(socket_mp->getSocketFd(), events);
            }

            base::PollEvents                       event_m;
            HttpClientManager::EventCallback       callback_m;
            bool                                   isStopped_m;
            std::shared_ptr<base::TcpSocket>       socket_mp{nullptr};
            int                                    epfd_m{0};
    };

}
#endif
