#!/bin/bash

_pwd="$PWD"
_reftag="v3.10.0-stable"
_certs=(
    certs/ca-cert.pem
    certs/client-cert.pem
    certs/dh2048.pem
    certs/ntru-key.raw
    certs/server-cert.pem
    certs/server-key.pem
)


if test ! -d wolfssl
then
    echo "Fetching wolfssl from GitHub"
    git clone https://github.com/wolfSSL/wolfssl.git
fi

echo "Cleanup from previous run"
rm -rf abi-ready local server certs wolfssl/support/wolfssl.pc
mkdir -p local certs

pushd wolfssl

git checkout master
git fetch origin
git reset --hard origin/master

echo "Building the server tool"
./autogen.sh >/dev/null 2>&1
./configure --disable-dependency-tracking --disable-shared >/dev/null
make examples/server/server >/dev/null
cp examples/server/server "$_pwd"
cp "${_certs[@]}" "$_pwd/certs"

git checkout "$_reftag" >/dev/null 2>&1
./autogen.sh >/dev/null 2>&1
./configure --disable-dependency-tracking --disable-static --prefix="$_pwd/local" >/dev/null
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

gcc -o client client.c -L./local/lib -I./local/include -lwolfssl
./server -d -i -p 0 -R abi-ready &
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
git checkout master
./autogen.sh >/dev/null 2>&1
./configure --disable-dependency-tracking --disable-static --prefix="$_pwd/local" >/dev/null
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
rm -f abi-ready

echo "end"
