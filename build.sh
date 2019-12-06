#!/bin/bash

prefix_path=$1
nghttp2_url="https://github.com/nghttp2/nghttp2/releases/download/v1.39.2/nghttp2-1.39.2.tar.gz"
libcurl_url="https://github.com/curl/curl/releases/download/curl-7_66_0/curl-7.66.0.tar.gz"

if [ -z "$prefix_path" ]
  then
    echo "No argument supplied, using current directory"
    prefix_path=$(pwd)
fi

# *********************** Build nghttp2 ***************************

nghttp2_prefix_path="${prefix_path}/nghttp2_install"

echo "Building nghtt2 library, prefix path:" $nghttp2_prefix_path
sleep 3

mkdir -p "$nghttp2_prefix_path"

wget $nghttp2_url

tar -zxvf nghttp2-*.gz
rm -rf nghttp2-*.gz

cd nghttp2-*
./configure --prefix=$nghttp2_prefix_path --enable-lib-only --disable-assert --disable-silent-rules
sleep 3
make
make install
cd -

# *********************** Build libcurl ***************************

libcurl_prefix_path="${prefix_path}/curl_install"

printf "\n\n"
echo "Now building libcurl, prefix path:" $libcurl_prefix_path
sleep 3

mkdir -p "$libcurl_prefix_path"

wget $libcurl_url

tar -zxvf curl-*.gz
rm -rf  curl-*.gz

cd curl-*
./configure --prefix=$libcurl_prefix_path --with-nghttp2=$nghttp2_prefix_path --disable-pthreads --disable-threaded-resolver --enable-debug --enable-curldebug --disable-silent-rules
sleep 3
make
make install
cd -


# *********************** Build Simulator ***************************
set -e
make -f Makefile cpath=$libcurl_prefix_path npath=$nghttp2_prefix_path

