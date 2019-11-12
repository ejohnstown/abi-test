#!/bin/bash

_pwd="$PWD"
_reftag="v3.10.0-stable"
_certs=(
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
rm -rf local server certs wolfssl/support/wolfssl.pc
mkdir -p local certs

pushd wolfssl

git checkout master
git fetch origin
git reset --hard origin/master

echo "Building the server tool"
./autogen.sh
./configure --disable-dependency-tracking --disable-shared
make examples/server/server
cp examples/server/server "$_pwd"
cp "${_certs[@]}" "$_pwd/certs"

git checkout "$_reftag"
./autogen.sh
./configure --disable-dependency-tracking --disable-static --prefix="$_pwd/local"
make install
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

gcc main.c -L./local/lib -I./local/include -lwolfssl
./server -d &
if ! ./a.out
then
    echo "case 1: Expected success, failed. Fail."
    exit 1
fi

rm -f "local/lib/$_oln"
if ./a.out
then
    echo "case 2: Expected failure, passed. Fail."
    exit 1
fi

echo "Installing current wolfSSL"
pushd wolfssl
rm -f support/wolfssl.pc
git checkout master
./autogen.sh
./configure --disable-dependency-tracking --disable-static --prefix="$_pwd/local"
make install
popd
if ./a.out
then
    echo "case 3: Expected failure, passed. Fail."
    exit 1
fi

echo "linking old library to current library"
pushd local/lib
ln -sf "$_ln" "$_oln"
popd
./server -d &
if ! ./a.out
then
    echo "case 4: Expected success, failed. Fail."
    exit 1
fi

