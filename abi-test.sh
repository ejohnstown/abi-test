#!/bin/bash

_pwd="$PWD"
#_reftag="v3.10.0-stable"
#_repo="https://github.com/wolfSSL/wolfssl.git"
#_curtag="master"
_repo="https://github.com/ejohnstown/wolfssl.git"
_reftag="abi-new-test"
_mastertag="master"

_certs=(
    certs/ca-cert.pem
    certs/client-cert.pem
    certs/dh2048.pem
    certs/ntru-key.raw
    certs/server-cert.pem
    certs/server-key.pem
    certs/test/server-localhost.pem
)

_confcli=(
    --disable-dependency-tracking
    --disable-static
    --enable-alpn
    --enable-pkcallbacks
    --enable-opensslextra
    --enable-sessioncerts
    --enable-sni
    --enable-tls13
    --prefix="$_pwd/local"
)
_confsrv=(
    --disable-dependency-tracking
    --disable-shared
    --enable-alpn
    --enable-sni
    --enable-tls13
)

echo "client: ./configure ${_confcli[@]}"
echo "server: ./configure ${_confsrv[@]}"


if test ! -d wolfssl
then
    echo "Fetching $_repo from GitHub"
    git clone "$_repo" wolfssl
fi

echo "Cleanup from previous run"
rm -rf abi-ready local server certs wolfssl/support/wolfssl.pc
mkdir -p local certs

pushd wolfssl

git checkout "$_mastertag"
git fetch origin
git reset --hard origin/"$_mastertag"

echo "Building the server tool"
./autogen.sh >/dev/null 2>&1
./configure "${_confsrv[@]}" >/dev/null
make examples/server/server >/dev/null
cp examples/server/server "$_pwd"
cp "${_certs[@]}" "$_pwd/certs"

git checkout "$_reftag" >/dev/null 2>&1
git reset --hard origin/"$_reftag"
./autogen.sh >/dev/null 2>&1
./configure "${_confcli[@]}" >/dev/null
make install >/dev/null
popd

export LD_LIBRARY_PATH="$_pwd/local/lib"

echo "updating library link"
case "$(ls $_pwd/local/lib)" in
*.dylib*)
    _oln="libwolfssl.3.dylib"
    _ln="libwolfssl.dylib"
    ;;
*.so*)
    _oln="libwolfssl.so.3"
    _ln="libwolfssl.so"
    ;;
esac

gcc -o client client.c -L./local/lib -I./local/include -lwolfssl -lm
./server -c ./certs/server-localhost.pem -v d -d -i -p 0 -R abi-ready &
_pid=$!

_counter=0
while test ! -s abi-ready -a "$_counter" -lt 20
do
	echo "waiting for ready file..."
	sleep 0.1
	_counter=$((_counter+1))
done

echo "case 1: built and run with old library"
if ! ./client "$(cat abi-ready)"
then
    echo "case 1: Expected success, failed. Fail."
	kill $_pid
    exit 1
fi

echo "Vaporize local install directory"
rm -rf local

echo "case 2: no library"
if ./client "$(cat abi-ready)"
then
    echo "case 2: Expected failure, passed. Fail."
	kill $_pid
    exit 1
fi

echo "Installing current wolfSSL"
pushd wolfssl
rm -f support/wolfssl.pc
git checkout "$_mastertag"
./autogen.sh >/dev/null 2>&1
./configure "${_confcli[@]}" >/dev/null
make install >/dev/null
popd

echo "case 3: built with old library, running with new"
if ./client "$(cat abi-ready)"
then
    echo "case 3: Expected failure, passed. Fail."
	kill $_pid
    exit 1
fi

echo "linking old library to current library"
pushd local/lib
ln -sf "$_ln" "$_oln"
popd

echo "case 4: built with old library, running with new linked as old"
if ! ./client "$(cat abi-ready)"
then
    echo "case 4: Expected success, failed. Fail."
	kill $_pid
    exit 1
fi

kill $_pid >/dev/null 2>&1

echo "end"
