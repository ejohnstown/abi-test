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
_oln="libwolfssl.3.dylib"
_ln="libwolfssl.dylib"


function runTest {
    ./server -d &
    _pid="$!"
    ./a.out
    kill -9 "$_pid"
}


if test ! -d wolfssl
then
    echo "Fetching wolfssl from GitHub"
    git clone git@github.com:wolfSSL/wolfssl.git
fi

echo "Cleanup from previous run"
rm -rf local server certs wolfssl/support/wolfssl.pc
mkdir -p local certs

pushd wolfssl

git checkout master
git fetch origin
git reset --hard origin/master

./autogen.sh
./configure --disable-dependency-tracking --disable-shared
make examples/server/server
cp examples/server/server "$_pwd"
cp "${_certs[@]}" "$_pwd/certs"

if test ! -d ABI_OLD
then
    git worktree add ABI_OLD "$_reftag"
    pushd ABI_OLD
    ./autogen.sh
    ./configure --disable-dependency-tracking --disable-static --prefix="$_pwd/local"
    popd
fi

cd ABI_OLD
make install
popd

gcc main.c -L./local/lib -I./local/include -lwolfssl
runTest

rm -f "local/lib/$_oln"
runTest

pushd wolfssl
./configure --disable-dependency-tracking --disable-static --prefix="$_pwd/local"
make install
popd
runTest

pushd local/lib
ln -sf "$_ln" "$_oln"
popd
runTest

