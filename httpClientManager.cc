#include "httpClientManager.h"
#include <sys/timerfd.h>

using namespace base;

HttpClientManager::HttpClientManager(unsigned int maxConnects, 
        unsigned int maxConnectsPerHost, 
        unsigned int maxParallelConnects,
        unsigned int dnsCacheTimeOut)
{
    curl_global_init(CURL_GLOBAL_ALL);

    HttpSharedHandle::getInstance()->SetShareDns(true);

    multi_handle_m = curl_multi_init();
    curl_multi_setopt(multi_handle_m, CURLMOPT_TIMERFUNCTION, CurlTimerCallback);
    curl_multi_setopt(multi_handle_m, CURLMOPT_TIMERDATA, this);
    curl_multi_setopt(multi_handle_m, CURLMOPT_SOCKETFUNCTION, CurlSocketCallback);
    curl_multi_setopt(multi_handle_m, CURLMOPT_SOCKETDATA, this);

    curl_multi_setopt(multi_handle_m, CURLMOPT_MAXCONNECTS, maxConnects);
    curl_multi_setopt(multi_handle_m, CURLMOPT_MAX_HOST_CONNECTIONS, maxConnectsPerHost);
    curl_multi_setopt(multi_handle_m, CURLMOPT_MAX_TOTAL_CONNECTIONS, maxParallelConnects);

    curl_multi_setopt(multi_handle_m, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);
    dnsCacheTimeOut_m = dnsCacheTimeOut;

    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if(epfd == -1) {
        perror("epoll_create1 failed");
        exit(1);
    }
    epollFd_m = epfd;
    tfd_m = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if(tfd_m == -1) {
        perror("timerfd_create failed");
    }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = tfd_m;
    epoll_ctl(epollFd_m, EPOLL_CTL_ADD, tfd_m, &ev);

    LOG_DEBUG("Initialized http libcurl multi handle"
            "CURLMOPT_MAXCONNECTS:%d CURLMOPT_MAX_HOST_CONNECTIONS:%d CURLMOPT_MAX_TOTAL_CONNECTIONS:%d", maxConnects ,maxConnectsPerHost, maxParallelConnects);

    socketsTable_m.clear();
    watchersTable_m.clear();
}


HttpClientManager::~HttpClientManager() 
{
    // when client mgr is being destructed, remove all the handles from the map
    if(!runningConnections_m.empty())
    {
        for(auto const &entry : runningConnections_m)
        {
            entry.second->SetVerbose(false);
            (void)AbortConnection(entry.second); // ignore return value
        }
        runningConnections_m.clear();
    }

    curl_multi_cleanup(multi_handle_m); 
}

std::error_condition HttpClientManager::StartConnection(const std::shared_ptr<HttpRequest>& connection) {

    std::error_condition error;

    connection->SetDnsCacheTimeOut(dnsCacheTimeOut_m); 

    CURL* easy_handle = connection->GetHandle();

    auto iterator = runningConnections_m.find(easy_handle);
    if (iterator != runningConnections_m.end()) {
        LOG_DEBUG("Try to start an already running connection, Ignored"
                "connectionName:%s" , connection->GetUrl().c_str());

        int er = static_cast<int>(HttpClientStatusCode::HTTP_LIB_INTERNAL);
        error.assign(er, HttpLibErrorCategory());
        return error;
    }

    LOG_DEBUG("Starting a connection"
            "connectionName:%s" , connection->GetUrl().c_str());

    curl_easy_setopt(easy_handle, CURLOPT_OPENSOCKETFUNCTION, CurlOpenSocketCallback);
    curl_easy_setopt(easy_handle, CURLOPT_OPENSOCKETDATA, this);
    curl_easy_setopt(easy_handle, CURLOPT_CLOSESOCKETFUNCTION, CurlCloseSocketCallback);
    curl_easy_setopt(easy_handle, CURLOPT_CLOSESOCKETDATA, this);


    connection->CheckAndSetUpHttpBodyUpload();
    connection->InitStart();
    connection->SetTcpKeepAlive(true);

    iterator = runningConnections_m.insert(std::make_pair(easy_handle, connection)).first;

    CURLMcode result = curl_multi_add_handle(multi_handle_m, easy_handle);
    if (result != CURLM_OK) {
        LOG_DEBUG("curl_multi_add_handle failed result:%d", static_cast<int>(result));

        runningConnections_m.erase(iterator);
        error.assign(result, CurlMultiErrorCategory());
        return error;
    }

    LOG_DEBUG("Startconnection return");
    int er = static_cast<int>(HttpClientStatusCode::HTTP_SEND_SUCCESS);
    error.assign(er, HttpLibErrorCategory());

    return error;
}


std::error_condition HttpClientManager::AbortConnection(const std::shared_ptr<HttpRequest>& connection) {

    std::error_condition error;

    if(connection == nullptr)
    {
        int er = static_cast<int>(HttpClientStatusCode::HTTP_REQUEST_CANCEL_FAILED);
        error.assign(er, HttpLibErrorCategory());
        return error;
    }

    CURL* easy_handle = connection->GetHandle();

    if(easy_handle == nullptr)
    {
        int er = static_cast<int>(HttpClientStatusCode::HTTP_REQUEST_CANCEL_FAILED);
        error.assign(er, HttpLibErrorCategory());
        return error;
    } 

    auto iterator = runningConnections_m.find(easy_handle);
    if (iterator == runningConnections_m.end()) {

        LOG_DEBUG("Try to abort a not running connection Ignored"
                " connectionName :%s" , connection->GetUrl().c_str());

        int er = static_cast<int>(HttpClientStatusCode::HTTP_LIB_INTERNAL);
        error.assign(er, HttpLibErrorCategory());
        return error;
    }

    LOG_DEBUG("Aborting a connection"
            "connectionName: %s", connection->GetUrl().c_str());

    runningConnections_m.erase(iterator);

    CURLMcode result = curl_multi_remove_handle(multi_handle_m, easy_handle);
    if (result != CURLM_OK) {
        LOG_ERROR("curl_multi_remove_handle failed"
                "result:%d", static_cast<int>(result));

        error.assign(result, CurlMultiErrorCategory());
    }

    int er = static_cast<int>(HttpClientStatusCode::HTTP_REQUEST_CANCEL_SUCCESS);
    error.assign(er, HttpLibErrorCategory());
    return error;
}


curl_socket_t HttpClientManager::OpenSocket(curlsocktype socket_type, curl_sockaddr* address) {

    LOG_DEBUG("Open socket"
            "type:%d address family:%d socket type:%d protocol:%d",  static_cast<int>(socket_type),
            address->family,
            address->socktype,
            address->protocol);

    curl_socket_t socket = this->Open(socket_type, address);

    if (socket != CURL_SOCKET_BAD) {
        LOG_DEBUG("Socket opened socket:%d", socket);
    }
    else {
        LOG_ERROR("eventName Open socket failed.");
    }

    return socket;
}


bool HttpClientManager::CloseSocket(curl_socket_t socket) {

    LOG_DEBUG( "Close socket:%d" , socket);

    bool is_succeeded = this->Close(socket);

    if (is_succeeded) {
        LOG_DEBUG("Socket closed successfully"
                "socket:%d", socket);
    } else {
        LOG_ERROR("Close Socket failed"
                "socket:%d", socket);
    }

    return is_succeeded;
}

void HttpClientManager::StopHttpTimer() {
    LOG_DEBUG("Stop Timer ");
    struct itimerspec its;
    memset(&its, 0, sizeof(struct itimerspec));
    timerfd_settime(tfd_m, 0, &its, NULL);
}

void HttpClientManager::StartHttpTimer(unsigned long timeout_ms) {
    LOG_DEBUG("StartHttpTimer timeout ms:%d", timeout_ms);

    struct itimerspec its;
    memset(&its, 0, sizeof(struct itimerspec));
    its.it_interval.tv_sec = 0;
    its.it_interval.tv_nsec = 0;
    its.it_value.tv_sec = timeout_ms / 1000;
    its.it_value.tv_nsec = (timeout_ms % 1000) * 1000 * 1000;

    LOG_DEBUG("Starting Timer for:%d", its.it_value.tv_sec);

    timerfd_settime(tfd_m, 0, &its, NULL);

}

void HttpClientManager::TimerTriggered() {

    LOG_DEBUG("Timer triggered.");

    int running_count = 0;
    curl_multi_socket_action(multi_handle_m, CURL_SOCKET_TIMEOUT, 0, &running_count);

    LOG_DEBUG("Timer triggered"
            "running_count:%d", running_count);

    CheckFinishedConnections();
}


void HttpClientManager::WatchSocket(curl_socket_t socket, int action, void* socket_pointer) {

    if (action == CURL_POLL_REMOVE) {
        LOG_DEBUG("Socket removed socket:%d", socket);
        this->StopWatching(socket);
        return;
    }
    LOG_DEBUG("Socket is added or modified"
            "socket:%d action:%d", socket, action);

    base::PollEvents event = 0;
    if(action != CURL_POLL_IN)
        event |= EPOLLOUT;
    if(action != CURL_POLL_OUT)
        event |= EPOLLIN;

    this->Watch(socket, event, std::bind(&HttpClientManager::SocketEventTriggered,
                this,
                std::placeholders::_1,
                std::placeholders::_2));
}


void HttpClientManager::SocketEventTriggered(curl_socket_t socket, base::PollEvents event) {

    LOG_DEBUG( "Socket event trigerred"
            "socket:%d eventval:%d socketevent:%s",  socket, event, ((event == EPOLLOUT) ? "write" : "read"));

    int action = 0; // Let libcurl decide action based on fd
    int running_count = 0;
    curl_multi_socket_action(multi_handle_m, socket, action, &running_count);
    CheckFinishedConnections();
}


void HttpClientManager::CheckFinishedConnections() {

    while (true) {

        int msg_count = 0;
        CURLMsg* msg = curl_multi_info_read(multi_handle_m, &msg_count);
        if (msg == nullptr) {
            break;
        }

        if (msg->msg == CURLMSG_DONE) {

            curl_multi_remove_handle(multi_handle_m, msg->easy_handle);

            auto iterator = runningConnections_m.find(msg->easy_handle);
            if (iterator != runningConnections_m.end()) {

                auto connection = iterator->second;
                const char *eff_url = connection->GetEffectiveUrl();
                runningConnections_m.erase(iterator);

                LOG_DEBUG("Connection finished"
                        " result_string:%s connection:%s result:%d",connection->GetResultString(), connection->GetUrl().c_str(),static_cast<int>(msg->data.result));

                if(eff_url != nullptr) {
                    LOG_DEBUG("Connection finished url:%s", eff_url);
                }

                connection->Finished(msg->data.result);
            }
        }
    }
}


curl_socket_t HttpClientManager::CurlOpenSocketCallback(void* clientp,
        curlsocktype socket_type,
        curl_sockaddr* address) {

    HttpClientManager* manager = static_cast<HttpClientManager*>(clientp);
    return manager->OpenSocket(socket_type, address);
}


int HttpClientManager::CurlCloseSocketCallback(void* clientp, curl_socket_t socket) {

    HttpClientManager* manager = static_cast<HttpClientManager*>(clientp);
    return manager->CloseSocket(socket);
}


int HttpClientManager::CurlTimerCallback(CURLM* multi_handle, long timeout_ms, void* user_pointer) {

    HttpClientManager* manager = static_cast<HttpClientManager*>(user_pointer);

    LOG_DEBUG("CurlTimerCallback"
            "timer:%d", timeout_ms);

    if (timeout_ms > 0) {
        manager->StartHttpTimer(timeout_ms);
    }
    else if (timeout_ms == 0) {
        LOG_DEBUG("timeout_ms 0");
        manager->TimerTriggered();
        //manager->StartHttpTimer(timeout_ms);
    }
    else {
        LOG_DEBUG("stop timeout_ms");
        manager->StopHttpTimer();
    }

    return 0;
}


int HttpClientManager::CurlSocketCallback(CURL* easy_handle,
        curl_socket_t socket,
        int action,
        void* user_pointer,
        void* socket_pointer) {

    HttpClientManager* manager = static_cast<HttpClientManager*>(user_pointer);
    LOG_DEBUG("CurlSocketCallback to start watch"
            "action:%d socket:%d" , action, socket);

    manager->WatchSocket(socket, action, socket_pointer);
    return 0;
}


curl_socket_t HttpClientManager::Open(curlsocktype socket_type, const curl_sockaddr* address) 
{
    // Note : address: is peer address
    if ( (socket_type != CURLSOCKTYPE_IPCXN) || ((address->family != AF_INET) && (address->family != AF_INET6)) ) {
        return CURL_SOCKET_BAD;
    }

    std::shared_ptr<base::TcpSocket> tcpsock = nullptr;

    try
    {
        uint32_t podIp = inet_network("127.0.0.1"); 
        base::IpAddress ipAddr( htonl(podIp) );

        LOG_DEBUG("Open socket ip_address:%s", ipAddr.toString().c_str());
        tcpsock = std::make_shared<TcpSocket>(ipAddr);
    }
    catch(const std::exception& e)
    {
        LOG_DEBUG("Open socket error description:%s", e.what());
        return CURL_SOCKET_BAD;
    }

    LOG_DEBUG("Opened socket:%d", tcpsock->getSocketFd());

    tcpsock->setNoDelay(1);
    socketsTable_m.insert(std::make_pair(tcpsock->getSocketFd(), tcpsock));
    return tcpsock->getSocketFd();
}

bool HttpClientManager::Close(curl_socket_t socket) {

    auto iterator = socketsTable_m.find(socket);
    if (iterator == socketsTable_m.end()) {
        return false;
    }

    auto asyncsocket = iterator->second;
    socketsTable_m.erase(iterator);

    LOG_DEBUG("closed socket:%d" , asyncsocket->getSocketFd());

    asyncsocket.reset();
    return true;
}


void HttpClientManager::Watch(curl_socket_t socket, base::PollEvents event, const EventCallback& callback) {


    auto iterator = socketsTable_m.find(socket);
    if (iterator == socketsTable_m.end()){
        LOG_DEBUG("Watch socket failed, no entry in map socket:%d" , socket);
        return;
    }

    auto watch_iterator = watchersTable_m.find(socket);
    if (watch_iterator != watchersTable_m.end()) {
        auto watcher = watch_iterator->second;
        watcher->UpdateWatch(event);
        return;
    }

    auto watcher = std::make_shared<HttpSocketWatcher>(iterator->second, event, callback, epollFd_m);
    watcher->Start();
    watchersTable_m.insert(std::make_pair(socket, watcher));
}


void HttpClientManager::StopWatching(curl_socket_t socket) {

    auto iterator = watchersTable_m.find(socket);
    if (iterator == watchersTable_m.end()) {
        LOG_DEBUG("Stop Watch socket failed, no entry in map socket:%d " , socket);
        return;
    }

    auto watcher = iterator->second;
    watcher->Stop();
    watchersTable_m.erase(iterator);
}

void HttpClientManager::httpClientResponseCb(const std::shared_ptr<HttpRequest> httprequest)
{
    const char* body = nullptr;
    std::size_t length = 0;

    //get shared ptr from weak ptr
    HttpResponseReadyCallbackSharedPtr callbackPtr = httprequest->GetAppResponseCallback().lock();

    if (callbackPtr != nullptr) {
        std::string httpRspHdrs = httprequest->GetResponseHeader();
        auto url = httprequest->GetUrl();
        long response_code = httprequest->GetResponseCode();
        if (httprequest->IsSetWriteBodyCallback()) {
            //Since this transaction has not yet finished, we have to fetch resp code from received headers.
            response_code = httprequest->GetResponseCode(CURLE_OK);
        }

        if(!httpRspHdrs.empty())
            httprequest->ResetResponseHeader(); // headers to be sent only once-for watchers

        const std::string& httpRsp = httprequest->GetResponseBody();

        std::shared_ptr<std::string> rspBuf = nullptr;
        if (httprequest->IsSetWriteBodyCallback() && length > 0) {
            rspBuf = std::make_shared<std::string>(body, length);
        }
        else if (httpRsp.length() > 0) {
            rspBuf = std::make_shared<std::string>(httpRsp.c_str(), httpRsp.length());
        }

        HttpClientStatusCode sc = HttpClientStatusCode::HTTP_INVALID;
        // exclude internal range
        if ( response_code >= 100 &&
                (response_code < 460 || response_code > 499) )
            sc = HttpClientStatusCode::HTTP_SEND_SUCCESS;
        else
            sc = static_cast<HttpClientStatusCode>(response_code);

        HttpClientRspPtr httpRspPtr = std::make_shared<HttpClientResponse>(httprequest->GetCookie()->getId(), response_code, std::move(httpRspHdrs), rspBuf);
        (*callbackPtr)(httpRspPtr, sc);
    }
    else // route the response through msgRouter url match
    {
        LOG_DEBUG("APP CallBack not set HTTP response URL:%s Code:%d", httprequest->GetUrl().c_str(), httprequest->GetResponseCode());
    }

    return;
}


    std::shared_ptr<HttpRequest> HttpClientManager::createRequest
(
 std::string url,
 const std::unordered_map<std::string, std::string>& httpHeaders, 
 std::string buffer,
 base::HttpCookieShPtr cookie,
 const HttpResponseReadyCallbackSharedPtr& httpRspCb,
 bool h2
 )
{
    auto httpClientRequest = std::make_shared<HttpRequest>();

    if(httpClientRequest == nullptr) 
        return nullptr; 

    //httpClientRequest->SetPodIpV4("127.0.0.1");
    httpClientRequest->SetRequestTimeoutInSec(5);
    httpClientRequest->SetUrl(url);
    if (loglevel >= DEBUG_LEVEL)
        httpClientRequest->SetVerbose(true);
    httpClientRequest->SetHttpMethod(CniMsgType::get_c);
    httpClientRequest->SetFinishedCallback(std::bind(&HttpClientManager::httpClientResponseCb, this, std::placeholders::_1));
    httpClientRequest->SetAppResponseCallback(httpRspCb);

    auto sharedBuff = std::make_shared<std::string>(buffer);
    if(!buffer.empty())
        httpClientRequest->SetRequestBody(sharedBuff);

    httpClientRequest->SetRequestHeaders(std::move(httpHeaders));

    httpClientRequest->SetCookie(cookie);

    // HTTP/2 settings
    if (h2)
        httpClientRequest->SetHTTP2Transfer();

    return httpClientRequest;
}


