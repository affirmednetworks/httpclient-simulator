# httpclient-simulator
A HTTP client simulator using libcurl and libnghttp2 with binding layer in C++. HTTP/1.1, HTTP/2.0 transfers can be attempted using this.
-----------------------------------------------------------------------------------------------------------------------------------

This is a very basic HTTP client simulator using libcurl and nghttp2
It uses opensource test framework - catch2
The libcurl binding layer is written in C++
Testcases are written in curl_client_test.cc.


# Installation
Use build.sh to build the libraries first:- nghttp2 and libcurl followed by client simulator.
*The script pulls the library sources from github links which can be specified in the script*


# Usage
Run the simulator with the desired log level, **`1`** -`ERROR`, **`2`** - `INFO`, **`3`** - `DEBUG`.
The server should be running with desired settings as per test cases.
Use `Ctrl+C` to **terminate** the simulator.


# Example
```
$ ./clientSimulator -l 2
2019-12-05 05:21:51 | INFO    | curl_client_test.cc | ____C_A_T_C_H____T_E_S_T____0:272 | ASync HTTP URL:http://127.0.0.1:9090/test Txn:1

2019-12-05 05:21:52 | INFO    | curl_client_test.cc | httpResponse:219 |  --> HTTP resp code:200

2019-12-05 05:21:52 | INFO    | curl_client_test.cc | ____C_A_T_C_H____T_E_S_T____0:289 | ASync HTTP URL:http://127.0.0.1:9090/test Txn:1 Got response:200

2019-12-05 05:21:52 | INFO    | curl_client_test.cc | ____C_A_T_C_H____T_E_S_T____2:306 | ASync HTTP URL:http://127.0.0.1:9999/test Txn:2

2019-12-05 05:21:52 | INFO    | curl_client_test.cc | ____C_A_T_C_H____T_E_S_T____4:334 | ASync HTTP URL:http://127.0.0.1:9090/test Txn:3

2019-12-05 05:21:57 | INFO    | curl_client_test.cc | httpResponse:219 |  --> HTTP resp code:460

2019-12-05 05:21:57 | INFO    | curl_client_test.cc | ____C_A_T_C_H____T_E_S_T____4:351 | ASync HTTP URL:http://127.0.0.1:9090/test Txn:3 Got response:460

===============================================================================
All tests passed (9 assertions in 3 test cases)
```
