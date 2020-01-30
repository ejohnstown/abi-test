#!/bin/bash

# NOTE: in the follow list of options, disable rsa may be removed
# before use. There is a bug in one of the test branches that has
# since been fixed in master.

_conf=(
    --disable-rsa
    --disable-examples
    --disable-static
    --enable-alpn
    --enable-pkcallbacks
    --enable-opensslextra
    --enable-sessioncerts
    --enable-sni
    --enable-tls13
)

function check_tool() {
    for _tool in "$@"
    do
        if ! command -v "$_tool" >/dev/null
        then
            >&2 echo "$_tool missing"
            exit 1
        fi
    done
}

function dump_abi() {
    if test ! -x "$1"
    then
        >&2 echo "shared library to dump doesn't exist"
        exit 1
    fi

    if ! abi-dumper -o "$2" -lver "$3" "$1"
    then
        >&2 echo "library dump failed"
        exit 2
    fi
}

function generate_report() {
    if test ! -f "$2"
    then
        >&2 echo "control dump doesn't exist"
        exit 1
    fi
    if test ! -f "$3"
    then
        >&2 echo "check dump doesn't exist"
        exit 1
    fi

    rm -f "$f"
    abi-compliance-checker -xml -lib "$1" -old "$2" -new "$3" -report-path "$4"
    if test ! -f "$4"
    then
        >&2 echo "generate report failed"
        exit 1
    fi
}

check_tool "abi-dumper" "abi-compliance-checker" "git" "gcc"

echo "Building check library"
./autogen.sh
./configure CFLAGS="-g -Og" "${_conf[@]}"
make
dump_abi "./src/.libs/libwolfssl.so" "./check.dump" "test-branch"

echo "Building control library"
git checkout -B control v4.3.0-stable
./autogen.sh
./configure CFLAGS="-g -Og" "${_conf[@]}"
make
dump_abi "./src/.libs/libwolfssl.so" "./control.dump" "v4.3.0-stable"

generate_report "wolfSSL" "./control.dump" "./check.dump" "./report.xml"
