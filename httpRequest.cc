#include "httpRequest.h"

using namespace base;

static std::string MakeHttpHeaderLine(const std::string& field, const std::string& value);
static std::vector<std::string> SplitString(const std::string& string, const std::string& delimiter);
std::atomic<uint32_t> HttpCookie::cookie_m=ATOMIC_VAR_INIT(0);

HttpRequest::HttpRequest() :
    isRunning_m(false),
    dnsResolveItems_mp(nullptr),
    requestBodyReadLength_m(0),
    result_m(CURL_LAST),
    requestHeaders_mp(nullptr),
    hasParsedResponseHeaders_m(false) {
        handle_mp = curl_easy_init();
        SetInitialOptions();
    }


HttpRequest::~HttpRequest() {
    ReleaseDnsResolveItems();
    curl_easy_cleanup(handle_mp);
    ReleaseRequestHeaders();
}


void HttpRequest::SetRequestHeaders(const std::unordered_map<std::string, std::string>& headers) {

    ReleaseRequestHeaders();

    for (auto& each_header : headers) {

        std::string each_header_line = MakeHttpHeaderLine(each_header.first, each_header.second);
        requestHeaders_mp = curl_slist_append(requestHeaders_mp, each_header_line.c_str());
    }

    curl_easy_setopt(GetHandle(), CURLOPT_HTTPHEADER, requestHeaders_mp);
}

void HttpRequest::AddRequestHeaders(const std::unordered_map<std::string, std::string>& headers) {

    for (auto& each_header : headers) {

        std::string each_header_line = MakeHttpHeaderLine(each_header.first, each_header.second);
        requestHeaders_mp = curl_slist_append(requestHeaders_mp, each_header_line.c_str());
    }

    curl_easy_setopt(GetHandle(), CURLOPT_HTTPHEADER, requestHeaders_mp);
}

void HttpRequest::AddRequestHeader(const std::string& field, const std::string& value) {

    std::string header_line = MakeHttpHeaderLine(field, value);
    requestHeaders_mp = curl_slist_append(requestHeaders_mp, header_line.c_str());

    curl_easy_setopt(GetHandle(), CURLOPT_HTTPHEADER, requestHeaders_mp);
}

const std::multimap<std::string, std::string>& HttpRequest::GetResponseHeaders() const {

    if (! hasParsedResponseHeaders_m) {
        ParseResponseHeaders();
        hasParsedResponseHeaders_m = true;
    }

    return responseHeaders_m;
}

void HttpRequest::ParseResponseHeaders() const {

    std::vector<std::string> lines = SplitString(GetResponseHeader(), "\r\n");

    std::vector<std::string> key_value_pair;
    for (auto& each_line : lines) {

        key_value_pair = SplitString(each_line, ": ");
        if (key_value_pair.size() < 2) {
            continue;
        }

        responseHeaders_m.insert(std::make_pair(key_value_pair.at(0), key_value_pair.at(1)));
    }
}

void HttpRequest::ResetResponseStates() {

    ResetResponseStatesB();

    hasParsedResponseHeaders_m = false;
    responseHeaders_m.clear();
}

void HttpRequest::ReleaseRequestHeaders() {

    if (requestHeaders_mp != nullptr) {
        curl_slist_free_all(requestHeaders_mp);
        requestHeaders_mp = nullptr;
    }
}

static std::string MakeHttpHeaderLine(const std::string& field, const std::string& value) {

    std::string header_line = field;
    header_line.append(": ");
    header_line.append(value);

    return header_line;
}

static std::vector<std::string> SplitString(const std::string& string, const std::string& delimiter) {

    std::vector<std::string> splitted_strings;

    std::size_t begin_index = 0;
    std::size_t end_index = 0;

    while (begin_index < string.length()) {

        end_index = string.find(delimiter, begin_index);

        if (end_index == std::string::npos) {
            end_index = string.length();
        }

        splitted_strings.push_back(string.substr(begin_index, end_index - begin_index));

        begin_index = end_index + delimiter.length();
    }

    return splitted_strings;
}

void HttpRequest::SetRequestTimeoutInSec(uint16_t time)
{
    curl_easy_setopt(GetHandle(), CURLOPT_TIMEOUT, time);
}

void HttpRequest::SetRequestTimeoutInMilliSec(unsigned long time)
{
    curl_easy_setopt(GetHandle(), CURLOPT_TIMEOUT_MS, time);
}

void HttpRequest::Start() 
{
    if (GetHTTP2Transfer() == base::HttpTransferFlag::HTTP2_PRIOR_KNOWLEDGE)
        curl_easy_setopt(GetHandle(), CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);

    CheckAndSetUpHttpBodyUpload();
    if (! isRunning_m) {
        InitStart();

        curl_easy_setopt(handle_mp, CURLOPT_OPENSOCKETFUNCTION, CurlOpenSocketCallback);
        curl_easy_setopt(handle_mp, CURLOPT_OPENSOCKETDATA, this);
        curl_easy_setopt(handle_mp, CURLOPT_CLOSESOCKETFUNCTION, CurlCloseSocketCallback);
        curl_easy_setopt(handle_mp, CURLOPT_CLOSESOCKETDATA, this);


        CURLcode result = curl_easy_perform(handle_mp);
        Finished(result);
    }
}

void HttpRequest::SetInitialOptions() {

    curl_easy_setopt(handle_mp, CURLOPT_READFUNCTION, CurlReadBodyCallback);
    curl_easy_setopt(handle_mp, CURLOPT_READDATA, this);
    curl_easy_setopt(handle_mp, CURLOPT_HEADERFUNCTION, CurlWriteHeaderCallback);
    curl_easy_setopt(handle_mp, CURLOPT_HEADERDATA, this);
    curl_easy_setopt(handle_mp, CURLOPT_WRITEFUNCTION, CurlWriteBodyCallback);
    curl_easy_setopt(handle_mp, CURLOPT_WRITEDATA, this);
    curl_easy_setopt(handle_mp, CURLOPT_ERRORBUFFER, errorBuff_m);

    SetSharedHandle(true);
}

void HttpRequest::SetTcpKeepAlive(bool enabled, uint32_t keepAliveIdleTime, uint32_t keepAliveInterval) {
    curl_easy_setopt(handle_mp, CURLOPT_TCP_KEEPALIVE, enabled);
    curl_easy_setopt(handle_mp, CURLOPT_TCP_KEEPIDLE, keepAliveIdleTime);
    curl_easy_setopt(handle_mp, CURLOPT_TCP_KEEPINTVL, keepAliveInterval);
}

void HttpRequest::SetSharedHandle(bool enabled) {
    if(enabled)
        curl_easy_setopt(handle_mp, CURLOPT_SHARE, HttpSharedHandle::getInstance()->GetSharedNativeHandle());
    else
        curl_easy_setopt(handle_mp, CURLOPT_SHARE, nullptr);
}


void HttpRequest::ReleaseDnsResolveItems() {

    if (dnsResolveItems_mp != nullptr) {
        curl_slist_free_all(dnsResolveItems_mp);
        dnsResolveItems_mp = nullptr;
    }
}

void HttpRequest::SetVerbose(bool verbose) {
    curl_easy_setopt(handle_mp, CURLOPT_VERBOSE, verbose);
}

void HttpRequest::SetUrl(const std::string& url) {
    curl_easy_setopt(handle_mp, CURLOPT_URL, url.c_str());
    requestUrl_m = url;
}

void HttpRequest::SetDnsResolveItems(const std::multimap<std::string, std::string>& resolve_items) {

    ReleaseDnsResolveItems();

    for (const auto& each_pair : resolve_items) {

        std::string item_string;
        if (each_pair.second.empty()) {
            item_string.append(1, '-');
            item_string.append(each_pair.first);
        }
        else {
            item_string.append(each_pair.first);
            item_string.append(1, ':');
            item_string.append(each_pair.second);
        }
        dnsResolveItems_mp = curl_slist_append(dnsResolveItems_mp, item_string.c_str());
    }

    curl_easy_setopt(handle_mp, CURLOPT_RESOLVE, dnsResolveItems_mp);
}

void HttpRequest::SetReceiveBody(bool receive_body) {
    curl_easy_setopt(handle_mp, CURLOPT_NOBODY, ! receive_body);
}


void HttpRequest::SetConnectTimeoutInMilliseconds(long milliseconds) {
    curl_easy_setopt(handle_mp, CURLOPT_CONNECTTIMEOUT_MS, milliseconds);
}

void HttpRequest::SetTimeoutInMilliseconds(long milliseconds) {
    curl_easy_setopt(handle_mp, CURLOPT_TIMEOUT_MS, milliseconds);
}

void HttpRequest::SetDebugCallback(const DebugCallback& callback) {

    debugCallback_m = callback;

    if (debugCallback_m != nullptr) {
        curl_easy_setopt(handle_mp, CURLOPT_DEBUGFUNCTION, CurlDebugCallback);
        curl_easy_setopt(handle_mp, CURLOPT_DEBUGDATA, this);
    }
    else {
        curl_easy_setopt(handle_mp, CURLOPT_DEBUGFUNCTION, nullptr);
        curl_easy_setopt(handle_mp, CURLOPT_DEBUGDATA, nullptr);
    }
}

void HttpRequest::InitStart() {
    isRunning_m = true;
    ResetResponseStates();
}

void HttpRequest::ResetResponseStatesB() {

    requestBodyReadLength_m = 0;
    result_m = CURL_LAST;
    responseHeader_m.clear();
    responseBody_m.clear();
}


void HttpRequest::Finished(CURLcode result) {

    isRunning_m = false;
    result_m = result;    

    if (finishedCallback_m) {
        finishedCallback_m(this->shared_from_this());
    }
}


long HttpRequest::GetResponseCode(CURLcode cc) const {

    long response_code = 0;
    switch(cc)
    {
        case CURLE_OK:
            curl_easy_getinfo(handle_mp, CURLINFO_RESPONSE_CODE, &response_code);
            break;

        default:
        case CURLE_UNSUPPORTED_PROTOCOL:
        case CURLE_FAILED_INIT:
        case CURLE_WEIRD_SERVER_REPLY:
        case CURLE_REMOTE_ACCESS_DENIED: //  a service was denied by the server due to lack of access - when login fails this is not returned. 
        case CURLE_OUT_OF_MEMORY:
            response_code = (long)HttpClientStatusCode::HTTP_CLIENT_GENERIC_ERROR;
            break;

        case CURLE_COULDNT_RESOLVE_HOST:
            response_code = (long)HttpClientStatusCode::HTTP_COULD_NOT_RESOLVE_HOST;
            break;

        case CURLE_COULDNT_CONNECT:
            response_code = (long)HttpClientStatusCode::HTTP_COULD_NOT_CONNECT;
            break;

        case CURLE_OPERATION_TIMEDOUT: //txn timeout
            response_code = (long)HttpClientStatusCode::HTTP_REQUEST_TIMEOUT;
            break;

        case CURLE_GOT_NOTHING: // case when TCP goes down during txn
            response_code = (long)HttpClientStatusCode::HTTP_EMPTY_REPLY_FROM_SERVER;
            break;

        case CURLE_AGAIN: // socket error
            response_code = (long)HttpClientStatusCode::HTTP_TRANSPORT_ERROR;
            break;

        case CURLE_CHUNK_FAILED: // chunk callback returned error
            response_code = (long)HttpClientStatusCode::HTTP_CHUNKED_REQUEST_FAILURE;
            break;
    }
    return response_code;
}


long HttpRequest::GetResponseCode() const {
    return this->GetResponseCode(result_m); 
}


bool HttpRequest::ReadBody(char* body, std::size_t expected_length, std::size_t& actual_length) {

    LOG_DEBUG("ReadBody bufferSize:%d", expected_length);

    bool is_succeeded = false;

    if (readBodyCallback_m) {
        is_succeeded = readBodyCallback_m(this->shared_from_this(), body, expected_length, actual_length);
    }
    else {

        if (requestBody_m != nullptr) {
            //std::size_t remain_length = requestBody_m->currentMessageLength() - requestBodyReadLength_m;
            std::size_t remain_length = requestBody_m->length() - requestBodyReadLength_m;
            actual_length = std::min(remain_length, expected_length);

            std::memcpy(body, (void *)&requestBody_m.get()[requestBodyReadLength_m], actual_length);
            requestBodyReadLength_m += actual_length;
        }

        is_succeeded = true;
    }

    if (is_succeeded) {
        LOG_DEBUG("ReadBody Done size:%d", actual_length);
    }
    else {
        LOG_ERROR("ReadBody Failed");
    }

    return is_succeeded;
}


bool HttpRequest::WriteHeader(const char* header, std::size_t length) {

    LOG_DEBUG("WriteHeader length:%d", length);

    bool is_succeeded = false;

    if (writeHeaderCallback_m) {
        is_succeeded = writeHeaderCallback_m(this->shared_from_this(), header, length);
    }
    else {
        responseHeader_m.append(header, length);
        is_succeeded = true;
    }

    LOG_DEBUG("WriteHeader result:%s" , (is_succeeded ? "done" : "failed")); 

    return is_succeeded;
}


bool HttpRequest::WriteBody(const char* body, std::size_t length) {

    LOG_DEBUG("WriteBody length:%d", length);

    bool is_succeeded = false;

    if (writeBodyCallback_m) {
        is_succeeded = writeBodyCallback_m(this->shared_from_this(), body, length);
    }
    else {
        responseBody_m.append(body, length);
        is_succeeded = true;
    }

    LOG_DEBUG("WriteBody result:%s", (is_succeeded ? "done" : "failed"));

    return is_succeeded;
}


void HttpRequest::Debug(HttpRequest::DebugDataType data_type, const char *data, std::size_t size) {

    if (debugCallback_m != nullptr) {
        debugCallback_m(shared_from_this(), data_type, data, size);
    }
}

size_t HttpRequest::CurlReadBodyCallback(char* buffer, size_t size, size_t nitems, void* instream) {
    HttpRequest* connection = static_cast<HttpRequest*>(instream);
    std::size_t actual_read_length = 0;
    bool is_succeeded = connection->ReadBody(buffer, size * nitems, actual_read_length);
    LOG_DEBUG("CurlReadBodyCallback is_succeeded:%d", is_succeeded);
    return is_succeeded ? actual_read_length : CURL_READFUNC_ABORT;
}


size_t HttpRequest::CurlWriteHeaderCallback(char* buffer, size_t size, size_t nitems, void* userdata) {
    std::size_t length = size * nitems;
    HttpRequest* connection = static_cast<HttpRequest*>(userdata);
    bool is_succeeded = connection->WriteHeader(buffer, length);
    return is_succeeded ? length : 0;
}

size_t HttpRequest::CurlWriteBodyCallback(char* ptr, size_t size, size_t nmemb, void* v) {
    std::size_t length = size * nmemb;
    HttpRequest* connection = static_cast<HttpRequest*>(v);
    bool is_succeeded = connection->WriteBody(ptr, length);
    return is_succeeded ? length : 0;
}

int HttpRequest::CurlDebugCallback(CURL* handle,
        curl_infotype type,
        char* data,
        size_t size,
        void* userptr) {

    if(userptr == nullptr)
        return 0;

    DebugDataType data_type = DebugDataType::Information;
    switch (type) {
        case CURLINFO_TEXT:
            break;
        case CURLINFO_HEADER_IN:
            data_type = DebugDataType::ReceivedHeader;
            break;
        case CURLINFO_HEADER_OUT:
            data_type = DebugDataType::SentHeader;
            break;
        case CURLINFO_DATA_IN:
            data_type = DebugDataType::ReceivedBody;
            break;
        case CURLINFO_DATA_OUT:
            data_type = DebugDataType::SentBody;
            break;
        case CURLINFO_SSL_DATA_IN:
            data_type = DebugDataType::ReceivedSslData;
            break;
        case CURLINFO_SSL_DATA_OUT:
            data_type = DebugDataType::SentSslData;
            break;
        default:
            break;
    }

    HttpRequest* request = static_cast<HttpRequest*>(userptr);
    request->Debug(data_type, data, size);
    return 0;
}

const char* HttpRequest::GetEffectiveUrl() const 
{
    char* eff_url = nullptr;
    curl_easy_getinfo(handle_mp, CURLINFO_EFFECTIVE_URL, &eff_url);
    return eff_url;
}


void HttpRequest::SetDnsCacheTimeOut (uint32_t timeout) 
{
    if(timeout > 0 )
        curl_easy_setopt(handle_mp, CURLOPT_DNS_CACHE_TIMEOUT, timeout);
}


curl_socket_t HttpRequest::CurlOpenSocketCallback(void* clientp,
        curlsocktype socket_type,
        curl_sockaddr* address) {

    HttpRequest* reqBase = static_cast<HttpRequest*>(clientp);
    return reqBase->OpenSocket(socket_type, address);
}


int HttpRequest::CurlCloseSocketCallback(void* clientp, curl_socket_t socket) {

    HttpRequest* reqBase = static_cast<HttpRequest*>(clientp);
    return reqBase->CloseSocket(socket);
}

curl_socket_t HttpRequest::OpenSocket(curlsocktype socket_type, curl_sockaddr* address) {

    // Note : address: is peer address
    if ( (socket_type != CURLSOCKTYPE_IPCXN) || ((address->family != AF_INET) && (address->family != AF_INET6)) ) {
        return CURL_SOCKET_BAD;
    }

    LOG_DEBUG("Open socket type: %d address family:%d socktype:%d protocol:%d" ,static_cast<int>(socket_type), address->family, address->socktype, address->protocol);

    try
    {
        base::IpAddress ipAddr( htonl(podIpV4_m) );

        LOG_DEBUG("Open socket ip_address:%s" , ipAddr.toString().c_str());
        tcpsock_m = std::make_shared<base::TcpSocket>(ipAddr);
    }
    catch(const std::exception& exp)
    {
        LOG_ERROR("Open socket error description:%s", exp.what());
        return CURL_SOCKET_BAD;
    }

    LOG_DEBUG("Opened socket socket:%d", tcpsock_m->getSocketFd());

    tcpsock_m->setNoDelay(1);
    return tcpsock_m->getSocketFd();

}

bool HttpRequest::CloseSocket(curl_socket_t socket) {

    LOG_DEBUG("Close socket socket:%d", socket);

    if(tcpsock_m != nullptr)
    {
        tcpsock_m.reset();
        return true;
    }
    return false;
}


void HttpRequest::SetPostSize(long size) {
    curl_easy_setopt(handle_mp, CURLOPT_POSTFIELDSIZE_LARGE, size);
}


void HttpRequest::SetHttpMethod(base::CniMsgType type)
{
    httpMethod_m = type;
    switch (type)
    {
        case base::CniMsgType::post_c:
            curl_easy_setopt(GetHandle(), CURLOPT_POST, 1L);
            break;

        case base::CniMsgType::del_c:
            curl_easy_setopt(GetHandle(),  CURLOPT_CUSTOMREQUEST, "DELETE");
            break;

        case base::CniMsgType::put_c:
            curl_easy_setopt(GetHandle(),  CURLOPT_CUSTOMREQUEST, "PUT");
            break;

        case base::CniMsgType::patch_c:
            curl_easy_setopt(GetHandle(),  CURLOPT_CUSTOMREQUEST, "PATCH");
            break;

        default:
        case base::CniMsgType::get_c:
            curl_easy_setopt(GetHandle(),  CURLOPT_CUSTOMREQUEST, "GET");
            break;
    }
}

void HttpRequest :: SetUpLoadHttpBody(bool enabled)
{
    if(enabled)
        curl_easy_setopt(GetHandle(),  CURLOPT_UPLOAD, 1L);
}

void HttpRequest::CheckAndSetUpHttpBodyUpload()
{
    switch (httpMethod_m)
    {
        default: 
        case base::CniMsgType::post_c:
            {
                auto buffer = GetRequestBody();
                if(buffer != nullptr) 
                    SetPostSize(buffer->length());
            }
            break;

        case base::CniMsgType::patch_c:
        case base::CniMsgType::put_c:
        case base::CniMsgType::del_c:
        case base::CniMsgType::get_c:
            {
                auto buffer = GetRequestBody();
                if(buffer != nullptr) 
                {
                    /* Note: Got requests other than POST and cutsom methods, CURLOPT_INFILESIZE_LARGE and 
                     * CURLOPT_UPLOAD has to be set */
                    SetUpLoadHttpBody(true);
                    curl_easy_setopt(handle_mp, CURLOPT_INFILESIZE_LARGE, buffer->length());
                }
                break;
            }
    }
}
