abi-test
========

make sure no *wolf* in /usr/local/lib

1) old version 3.10.0

git checkout v3.10.0-stable
./autogen
./configure --disable-static
make
sudo make install

2) build test app against 3.10.0  which is libwolfssl.3.dylib

gcc main.c -lwolfssl

run against a new (not 3.10.0 which has expired certs) example server

./examples/server/server -d

./a.out

hello
got a good ctx
load verify ret = 1
got a good ssl
ssl connect ret = 1
write ret = 9
read ret = 23
read I hear you fa shizzle!
bye

3) sudo make uninstall from old version

4) try to run ./a.out

dyld: Library not loaded: /usr/local/lib/libwolfssl.3.dylib
  Referenced from: /Users/toddouska/test/simple/./a.out
  Reason: image not found
Abort trap: 6

5) build new version

git checkout master
./autogen
./configure --disable-static
make
sudo make install

6) verify still doesn't work

./a.out

dyld: Library not loaded: /usr/local/lib/libwolfssl.3.dylib
  Referenced from: /Users/toddouska/test/simple/./a.out
  Reason: image not found
Abort trap: 6

7) create a soft link to new version, which would happen during binary library
update

sudo ln -sf libwolfssl.19.dylib libwolfssl.3.dylib

8) w/o recompiling or relinking we can now run against new version of library

./a.out

hello
got a good ctx
load verify ret = 1
got a good ssl
ssl connect ret = 1
write ret = 9
read ret = 23
read I hear you fa shizzle!
bye


abi-scan
========

Script to run abi-dumper on a commit under test and a control commit and
then runs abi-compliance-checker on the dump files to generate a report.
Also has a groovy script to process the report.
