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

#include "httpClientManager.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unordered_map>
#include <unistd.h>
#include <thread>
#include <future>
#include <numeric>

#define CATCH_CONFIG_RUNNER
#include "catch.hpp"

#define MSG_OUT stdout

//#define TEST_URL1 "www.example.org"
#define TEST_URL1 "http://127.0.0.1:9090/test"
#define TEST_URL2 "http://127.0.0.1:9999/test"
#define TEST_DATA ""


/* Global information, common to all connections */
typedef struct _GlobalInfo
{
  int epfd;    /* epoll filedescriptor */
  int tfd;    /* timer filedescriptor */
} GlobalInfo;


int g_should_exit_ = 0;

void SignalHandler(int signo)
{
  if(signo == SIGINT) {
    g_should_exit_ = 1;
  }
}

static HttpClientManager* httpClientMgr_m = nullptr;
int loglevel = 1;

int main(int argc, char **argv)
{
    std::shared_ptr<std::thread> t1;
    int opt = 0;
    while ((opt = getopt(argc, argv, "h:l:")) != -1)
    {
        switch (opt) {
            case 'l':
                loglevel = atoi(optarg);
                break;
            case 'p':
                break;
            default: /* '?' */
                fprintf(stderr, "Usage: %s [-l loglevel -> 1 err, 2 info, 3 debug] \n", argv[0]);
                //exit(EXIT_FAILURE);
                break;
        }

    }

    GlobalInfo g;
    struct itimerspec its;
    struct epoll_event ev;
    struct epoll_event events[10];

    g_should_exit_ = 0;
    signal(SIGINT, SignalHandler);

    LOG_DEBUG("HTTP Client Simulator");

    httpClientMgr_m = new HttpClientManager(HTTP_CLIENT_MAX_CONNECTS,
            HTTP_CLIENT_MAX_CONNECTS_PERHOST,
            HTTP_CLIENT_MAX_PARALLELCONNECTS,
            HTTP_DNS_CACHE_TIMEOUT_SECS);


    g.tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if(g.tfd == -1) {
        LOG_ERROR("timerfd_create failed");
        exit(1);
    }
    memset(&its, 0, sizeof(struct itimerspec));
    its.it_interval.tv_sec = 0;
    its.it_value.tv_sec = 3;
    timerfd_settime(g.tfd, 0, &its, NULL);

    ev.events = EPOLLIN;
    ev.data.fd = g.tfd;
    epoll_ctl(httpClientMgr_m->EPFD(), EPOLL_CTL_ADD, g.tfd, &ev);

    LOG_DEBUG("Entering wait loop\n");
    fflush(MSG_OUT);
    while(!g_should_exit_) {

        int idx;
        int err = epoll_wait(httpClientMgr_m->EPFD(), events,
                sizeof(events)/sizeof(struct epoll_event), 10000);
        if(err == -1) {
            if(errno == EINTR) {
                LOG_DEBUG("note: wait interrupted\n");
                continue;
            }
            else {
                LOG_ERROR("epoll_wait");
                exit(1);
            }
        }

        for(idx = 0; idx < err; ++idx) 
        {
            if(events[idx].data.fd == httpClientMgr_m->TFD()) {
                LOG_DEBUG("timer event\n");

                uint64_t count = 0;
                ssize_t err = 0;

                err = read(httpClientMgr_m->TFD(), &count, sizeof(uint64_t));
                if(err == -1) {
                    if(errno == EAGAIN) {
                        LOG_DEBUG("EAGAIN on tfd %d\n", httpClientMgr_m->TFD());
                        continue;
                    }
                }
                if(err != sizeof(uint64_t)) {
                    LOG_ERROR("read(tfd) == %ld", err);
                    LOG_ERROR("read(tfd)");
                }

                httpClientMgr_m->TimerTriggered();
            }
            else if(events[idx].data.fd == g.tfd) {
                LOG_DEBUG("Initial timer fired\n");
                uint64_t count = 0;
                ssize_t err = 0;

                err = read(g.tfd, &count, sizeof(uint64_t));
                if(err == -1) {
                    if(errno == EAGAIN) {
                        LOG_DEBUG("EAGAIN on tfd %d\n", g.tfd);
                        continue;
                    }
                }
                if(err != sizeof(uint64_t)) {
                    LOG_ERROR("read(tfd) == %ld", err);
                }

                for(int i=1; i<argc; ++i)
                    memset(argv[i], '\0', sizeof(argv[i])); 

                t1.reset(new std::thread([&](){
                            int result = Catch::Session().run( argc, argv );
                            }));

            }
            else {
                httpClientMgr_m->SocketEventTriggered(events[idx].data.fd, events[idx].events);
            }
        }
    }

    t1->join();

    LOG_DEBUG("Exiting normally.\n");
    fflush(MSG_OUT);

    return 0;
}

using HttpReqShPtr = std::shared_ptr<base::HttpRequest>;
typedef std::unordered_map<uint32_t, std::shared_ptr<base::HttpRequest>> HttpTidMap;
volatile int resultCode = 0;


class HttpResponse
{
    public:
        void httpResponse(const HttpClientRspPtr& httpRspPtr, HttpClientStatusCode sc) {
            LOG_DEBUG("HTTP resp recevied with sc:%d tid:%d\n", sc, httpRspPtr->getTid());
            auto req = findHttpTxn(httpRspPtr->getTid());
            if (req) {
                LOG_DEBUG("Found HTTP txn tid:%d\n", httpRspPtr->getTid());
                LOG_INFO(" --> HTTP resp code:%d\n", httpRspPtr->getRespCode());
                LOG_DEBUG(" --> HTTP resp hdrs:%s\n", httpRspPtr->getHttpRspHdrs().c_str());
                if (httpRspPtr->getHttpRspBuffer())
                    LOG_DEBUG(" --> HTTP resp buffer:%s\n", httpRspPtr->getHttpRspBuffer()->c_str());
            
                deleteHttpTxn(httpRspPtr->getTid());
                req->Promise().set_value(httpRspPtr->getRespCode());
            }
        }

        void insertHttpTxn(const uint32_t id, HttpReqShPtr req) {
            LOG_DEBUG( "Insert Http Txn:%d\n", id);
            httpTidMap_m.insert(std::pair<uint32_t, std::shared_ptr<base::HttpRequest>>(id, req));
        }

        HttpReqShPtr findHttpTxn(const uint32_t id) {
            LOG_DEBUG( "Find Http Txn:%d\n", id);
            HttpTidMap::iterator it = httpTidMap_m.find(id);
            if (it != httpTidMap_m.end()) {
                HttpReqShPtr reqPtr = it->second;
                return reqPtr;
            }
            return nullptr;
        }
        
        void deleteHttpTxn(const uint32_t id) {
            LOG_DEBUG( "Delete Http Txn:%d\n", id);
            HttpTidMap::iterator it = httpTidMap_m.find(id);
            if (it != httpTidMap_m.end()) {
                httpTidMap_m.erase(it);
            }
        }

    private:
        HttpTidMap httpTidMap_m;        
};

HttpResponse *hRespPtr = new HttpResponse();

HttpResponseReadyCallbackSharedPtr httpRespCbPtr = std::make_shared<HttpAsyncCallBack<HttpResponse>>(hRespPtr, &HttpResponse::httpResponse);

/*
 * TEST CASE 1: This would connect with TEST_URL1 for HTTP/2 transfer
 * expecting 200 response
 * */
TEST_CASE( "Async GET, PUT, POST, DELETE - 200", "[single-file]" ) {
    REQUIRE(httpClientMgr_m);
    std::unordered_map<std::string, std::string> httpReqHdrs;
    base::HttpCookieShPtr cookie = std::make_shared<base::HttpCookie>();
    bool http2 = true;
    auto req = httpClientMgr_m->createRequest(TEST_URL1, httpReqHdrs, TEST_DATA, cookie, httpRespCbPtr, http2);

    auto sc = HttpClientStatusCode::HTTP_SEND_SUCCESS;
    LOG_INFO( "ASync HTTP URL:%s Txn:%d\n", TEST_URL1, req->getCookieId());
    std::error_condition ec = httpClientMgr_m->StartConnection(req);
    if (ec.category().message(ec.value()) == "HttpLibcode")
        sc = static_cast<HttpClientStatusCode>(ec.value());
    else {
        auto cc = static_cast<CURLcode>(ec.value());
        sc = static_cast<HttpClientStatusCode>(req->GetResponseCode(cc));
    }

    REQUIRE(sc == HttpClientStatusCode::HTTP_SEND_SUCCESS);

    hRespPtr->insertHttpTxn(req->getCookieId(), req);

    std::future<int> response_future = req->Promise().get_future();
    response_future.wait();
    int rc = response_future.get();

    LOG_INFO( "ASync HTTP URL:%s Txn:%d Got response:%d\n", TEST_URL1, req->getCookieId(), rc);
    
    REQUIRE(rc == 200);
}

/*
 * TEST CASE 2: This would connect with TEST_URL2 for HTTP/2 transfer
 * expecting 499 response as the URL is invalid / no server listening on it
 * */
TEST_CASE( "Async GET - 463 - Invalid URL", "[single-file]" ) {
    REQUIRE(httpClientMgr_m);
    std::unordered_map<std::string, std::string> httpReqHdrs;
    base::HttpCookieShPtr cookie = std::make_shared<base::HttpCookie>();
    bool http2 = true;
    auto req = httpClientMgr_m->createRequest(TEST_URL2, httpReqHdrs, TEST_DATA, cookie, httpRespCbPtr, http2);
    
    auto sc = HttpClientStatusCode::HTTP_SEND_SUCCESS;
    LOG_INFO( "ASync HTTP URL:%s Txn:%d\n", TEST_URL2, req->getCookieId());
    std::error_condition ec = httpClientMgr_m->StartConnection(req);
    if (ec.category().message(ec.value()) == "HttpLibcode")
        sc = static_cast<HttpClientStatusCode>(ec.value());
    else {
        auto cc = static_cast<CURLcode>(ec.value());
        sc = static_cast<HttpClientStatusCode>(req->GetResponseCode(cc));
    }

    LOG_DEBUG( "HTTP send status:%d rc:%d\n", sc, req->GetResponseCode());

    REQUIRE(sc == HttpClientStatusCode::HTTP_SEND_SUCCESS);

    REQUIRE(499 == req->GetResponseCode());
}

/*
 * TEST CASE 3: This would connect with TEST_URL1 for HTTP/2 transfer
 * expecting 460 response code as server doesnt respond within request timeout
 * */
TEST_CASE( "Async GET - 460 - Timeout", "[single-file]" ) {
    REQUIRE(httpClientMgr_m);
    std::unordered_map<std::string, std::string> httpReqHdrs;
    base::HttpCookieShPtr cookie = std::make_shared<base::HttpCookie>();
    bool http2 = true;
    auto req = httpClientMgr_m->createRequest(TEST_URL1, httpReqHdrs, TEST_DATA, cookie, httpRespCbPtr, http2);

    auto sc = HttpClientStatusCode::HTTP_SEND_SUCCESS;
    LOG_INFO( "ASync HTTP URL:%s Txn:%d\n", TEST_URL1, req->getCookieId());
    std::error_condition ec = httpClientMgr_m->StartConnection(req);
    if (ec.category().message(ec.value()) == "HttpLibcode")
        sc = static_cast<HttpClientStatusCode>(ec.value());
    else {
        auto cc = static_cast<CURLcode>(ec.value());
        sc = static_cast<HttpClientStatusCode>(req->GetResponseCode(cc));
    }

    REQUIRE(sc == HttpClientStatusCode::HTTP_SEND_SUCCESS);

    hRespPtr->insertHttpTxn(req->getCookieId(), req);

    std::future<int> response_future = req->Promise().get_future();
    response_future.wait();
    int rc = response_future.get();

    LOG_INFO( "ASync HTTP URL:%s Txn:%d Got response:%d\n", TEST_URL1, req->getCookieId(), rc);
    
    REQUIRE(rc == 460);
}



