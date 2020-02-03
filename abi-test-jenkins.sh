#!/bin/bash

_reftag="v4.3.0-stable"
: ${CC="gcc"}
export CC

case "$#" in
0)
    ;;
1)
    if test "x$1" = "x--help" -o "x$1" = "x-h"
    then
        echo "Usage: $0 [REFTAG]"
        echo "REFTAG    - old commit to test against"
        exit 1
    fi

    _reftag="$2"
    ;;
*)
    echo "Usage: $0 [REFTAG]"
    echo "REFTAG    - old commit to test against"
    exit 1
    ;;
esac

_confcli=(
    --disable-dependency-tracking
    --disable-examples
    --disable-static
    --enable-alpn
    --enable-pkcallbacks
    --enable-opensslextra
    --enable-sessioncerts
    --enable-sni
    --enable-tls13
    --prefix="$PWD/local"
)
_confsrv=(
    --disable-dependency-tracking
    --disable-shared
    --enable-alpn
    --enable-sni
    --enable-tls13
)

# Save out the test client source code.
(
cat <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>

typedef struct sockaddr_in  SOCKADDR_IN_T;
#define SOCKET_T int
#define AF_INET_V    AF_INET


const char* caCert = "./certs/test/server-localhost.pem";
const char* clientCert = "./certs/client-cert.pem";
const char* clientKey = "./certs/client-key.pem";


static inline WC_NORETURN void
err_sys(const char* msg)
{
    fprintf(stderr, "wolfSSL error: %s\n", msg);

    exit(EXIT_FAILURE);
}


static inline
void build_addr(SOCKADDR_IN_T* addr, const char* peer, unsigned short port)
{
    int useLookup = 0;
    (void)useLookup;

    if (addr == NULL)
        err_sys("invalid argument to build_addr, addr is NULL");

    memset(addr, 0, sizeof(SOCKADDR_IN_T));

#ifndef TEST_IPV6
    /* peer could be in human readable form */
    if ( ((size_t)peer != INADDR_ANY) && isalpha((int)peer[0])) {
    #ifndef WOLFSSL_USE_GETADDRINFO
        #if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
            int err;
            struct hostent* entry = gethostbyname(peer, &err);
        #elif defined(WOLFSSL_TIRTOS)
            struct hostent* entry = DNSGetHostByName(peer);
        #elif defined(WOLFSSL_VXWORKS)
            struct hostent* entry = (struct hostent*)hostGetByName((char*)peer);
        #else
            struct hostent* entry = gethostbyname(peer);
        #endif

        if (entry) {
            memcpy(&addr->sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            useLookup = 1;
        }
    #else
        struct zsock_addrinfo hints, *addrInfo;
        char portStr[6];
        XSNPRINTF(portStr, sizeof(portStr), "%d", port);
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
        hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
        if (getaddrinfo((char*)peer, portStr, &hints, &addrInfo) == 0) {
            XMEMCPY(addr, addrInfo->ai_addr, sizeof(*addr));
            useLookup = 1;
        }
    #endif
        else
            err_sys("no entry for host");
    }
#endif


#ifndef TEST_IPV6
    #if defined(WOLFSSL_MDK_ARM) || defined(WOLFSSL_KEIL_TCP_NET)
        addr->sin_family = PF_INET;
    #else
        addr->sin_family = AF_INET_V;
    #endif
    addr->sin_port = htons(port);
    if ((size_t)peer == INADDR_ANY)
        addr->sin_addr.s_addr = INADDR_ANY;
    else {
        if (!useLookup)
            addr->sin_addr.s_addr = inet_addr(peer);
    }
#else
    addr->sin6_family = AF_INET_V;
    addr->sin6_port = XHTONS(port);
    if ((size_t)peer == INADDR_ANY) {
        addr->sin6_addr = in6addr_any;
    }
    else {
        #if defined(HAVE_GETADDRINFO) || defined(WOLF_C99)
            struct addrinfo  hints;
            struct addrinfo* answer = NULL;
            int    ret;
            char   strPort[80];

            XMEMSET(&hints, 0, sizeof(hints));

            hints.ai_family   = AF_INET_V;
            if (udp) {
                hints.ai_socktype = SOCK_DGRAM;
                hints.ai_protocol = IPPROTO_UDP;
            }
        #ifdef WOLFSSL_SCTP
            else if (sctp) {
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_SCTP;
            }
        #endif
            else {
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;
            }

            SNPRINTF(strPort, sizeof(strPort), "%d", port);
            strPort[79] = '\0';

            ret = getaddrinfo(peer, strPort, &hints, &answer);
            if (ret < 0 || answer == NULL)
                err_sys("getaddrinfo failed");

            XMEMCPY(addr, answer->ai_addr, answer->ai_addrlen);
            freeaddrinfo(answer);
        #else
            fprintf(stderr,
                    "no ipv6 getaddrinfo, loopback only tests/examples\n");
            addr->sin6_addr = in6addr_loopback;
        #endif
    }
#endif
}


static inline
void tcp_socket(SOCKET_T* sockfd)
{
    *sockfd = socket(AF_INET_V, SOCK_STREAM, IPPROTO_TCP);

    if(*sockfd < 0) {
        err_sys("socket failed\n");
    }

    signal(SIGPIPE, SIG_IGN);
}


static inline
void tcp_connect(SOCKET_T* sockfd, const char* ip, unsigned short port)
{
    SOCKADDR_IN_T addr;
    build_addr(&addr, ip, port);
    tcp_socket(sockfd);

    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp connect failed");
}


static
int print_time(const char* desc, const unsigned char* time)
{
    int length;
    unsigned char flatTime[64];
    unsigned char type;

    type = time[0];
    length = (int)time[1];

    memcpy(flatTime, &time[2], length);
    flatTime[length] = '\0';

    printf("  %12s: (%u) %s\n", desc, type, flatTime);

    return 0;
}


static
int print_cert(const char* desc, WOLFSSL_X509* cert)
{
    WOLFSSL_X509_NAME* xName;
    const unsigned char* xTime;
    char* nameP;
    char name[256];
    int ret, error = -1;

    printf("%s\n", desc);
    xName = wolfSSL_X509_get_issuer_name(cert);
    if (xName == NULL) {
        fprintf(stderr, "wolfSSL_X509_get_issuer_name() failed\n");
        goto doExit;
    }

    nameP = wolfSSL_X509_NAME_oneline(xName, name, (int)sizeof(name));
    if (nameP == NULL) {
        fprintf(stderr, "wolfSSL_X509_NAME_online() failed\n");
        goto doExit;
    }
    printf("  %12s: %s\n", "issuer name", nameP);

    xName = wolfSSL_X509_get_subject_name(cert);
    if (xName == NULL) {
        fprintf(stderr, "wolfSSL_X509_get_subject_name() failed\n");
        goto doExit;
    }

    nameP = wolfSSL_X509_NAME_oneline(xName, name, (int)sizeof(name));
    if (nameP == NULL) {
        fprintf(stderr, "wolfSSL_X509_NAME_online() failed\n");
        goto doExit;
    }
    printf("  %12s: %s\n", "subject name", nameP);

    do {
        nameP = wolfSSL_X509_get_next_altname(cert);
        if (nameP != NULL) {
            printf("  %12s: %s\n", "altname", nameP);
        }
    } while (nameP != NULL);

    xTime = wolfSSL_X509_notBefore(cert);
    if (xTime == NULL) {
        fprintf(stderr, "wolfSSL_X509_notBefore() failed\n");
        goto doExit;
    }

    ret = print_time("notBefore", xTime);
    if (ret != 0) {
        fprintf(stderr, "print_time() failed (%d)\n", ret);
        goto doExit;
    }

    xTime = wolfSSL_X509_notAfter(cert);
    if (xTime == NULL) {
        fprintf(stderr, "wolfSSL_X509_notAfter() failed\n");
        goto doExit;
    }

    ret = print_time("notAfter", xTime);
    if (ret != 0) {
        fprintf(stderr, "print_time() failed (%d)\n", ret);
        goto doExit;
    }

    error = 0;

doExit:
    return error;
}


static
int test_cert_file(void)
{
    WOLFSSL_X509* cert;
    int ret, error = -1;

    cert = wolfSSL_X509_load_certificate_file(caCert, SSL_FILETYPE_PEM);
    if (cert == NULL) {
        fprintf(stderr, "wolfSSL_X509_load_certificate_file() failed\n");
        goto doExit;
    }

    ret = print_cert("wolfSSL_X509_load_certificate_file()", cert);
    if (ret != 0) {
        fprintf(stderr, "print_cert() failed (%d)\n", ret);
        goto doCleanup;
    }

    error = 0;

doCleanup:
    wolfSSL_X509_free(cert);

doExit:
    return error;
}


static
int test_ecc_key(void)
{
    WC_RNG* rng = NULL;
    ecc_key* ecc = NULL;
    byte nonce[32];
    byte digest[32];
    byte sig[72];
    int ret = 0, error = -1;
    word32 digestSz = sizeof(digest), sigSz = sizeof(sig);

    memset(nonce, 0, sizeof(nonce));

    rng = wc_rng_new(nonce, (word32)sizeof(nonce), NULL);
    if (rng == NULL) {
        fprintf(stderr, "wc_rng_new() failed\n");
        goto doExit;
    }

    ret = wc_RNG_GenerateBlock(rng, digest, digestSz);
    if (ret != 0) {
        fprintf(stderr, "wc_RNG_GenerateBlock() failed (%d)\n", ret);
        goto doCleanup;
    }

    ecc = wc_ecc_key_new(NULL);
    if (ecc == NULL) {
        fprintf(stderr, "wc_ecc_key_new() failed\n");
        goto doCleanup;
    }

    ret = wc_ecc_init_ex(ecc, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "wc_ecc_init_ex() failed (%d)\n", ret);
        goto doCleanup;
    }

    ret = wc_ecc_make_key_ex(rng, 32, ecc, ECC_SECP256R1);
    if (ret != 0) {
        fprintf(stderr, "wc_ecc_make_key_ex() failed (%d)\n", ret);
        goto doCleanup;
    }

    ret = wc_ecc_sign_hash(digest, digestSz, sig, &sigSz, rng, ecc);
    if (ret != 0) {
        fprintf(stderr, "wc_ecc_sign_hash() failed (%d)\n", ret);
        goto doCleanup;
    }

    error = 0;

doCleanup:
    if (ecc != NULL) {
        wc_ecc_free(ecc);
        wc_ecc_key_free(ecc);
    }
    if (rng != NULL)
        wc_rng_free(rng);

doExit:
    return error;
}


static
int test_ecc_sign_cb(WOLFSSL* ssl,
       const unsigned char* in, unsigned int inSz,
       unsigned char* out, word32* outSz,
       const unsigned char* keyDer, unsigned int keySz,
       void* ctx)
{
    int ret, error = -1;
    ecc_key* ecc = NULL;

    (void)ctx;
    printf("EccSignCb\n");

    if (ssl == NULL) {
        fprintf(stderr, "test_ecc_sign_cb(): Bad function param\n");
        goto doExit;
    }

    ecc = wc_ecc_key_new(NULL);
    if (ecc == NULL) {
        fprintf(stderr, "wc_ecc_new() failed\n");
        goto doExit;
    }

    ret = wc_ecc_init_ex(ecc, NULL, INVALID_DEVID);
    if (ret != 0) {
        fprintf(stderr, "wc_ecc_init_ex() failed (%d)\n", ret);
        goto doCleanup;
    }

    ret = wc_ecc_import_x963(keyDer, keySz, ecc);
    if (ret != 0) {
        fprintf(stderr, "Couldn't import ECC key. (%d)\n", ret);
        goto doCleanup;
    }

    ret = wc_ecc_sign_hash(in, inSz, out, outSz, wolfSSL_GetRNG(ssl), ecc);
    if (ret != 0) {
        fprintf(stderr, "Couldn't sign the hash. (%d)\n", ret);
        goto doCleanup;
    }

    error = 0;

doCleanup:
    wc_ecc_free(ecc);
    wc_ecc_key_free(ecc);

doExit:
    return error;
}


static
int test_connection(int ver, int port)
{
    WOLFSSL_METHOD* method;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    WOLFSSL_X509* cert;
    WOLFSSL_SESSION* session;
    const char* sni;
    const byte* sessionId;
    char buffer[128];
    char alpnList[] = "C:";
    int ret = 0, error = -1;
    SOCKET_T sfd;
    long mode;

    printf("test_connection(%d, %d)\n", ver, port);
    switch (ver) {
        case 3:
            method = wolfTLSv1_3_client_method();
            ver = WOLFSSL_TLSV1_3;
            break;
        default:
            method = wolfTLSv1_2_client_method();
            ver = WOLFSSL_TLSV1_2;
    }

    if (method == NULL) {
        fprintf(stderr, "wolfTLSv1_%d_client_method() failed\n", ver - 1);
        goto doExit;
    }

    ctx = wolfSSL_CTX_new(method);
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new() failed\n");
        goto doExit;
    }

    ret = wolfSSL_CTX_SetMinVersion(ctx, ver);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_SetMinVersion() failed (%d)\n", ret);
        goto doCleanup;
    }

    ret = wolfSSL_CTX_load_verify_locations(ctx, caCert, 0);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_load_verify_locations() failed (%d)\n",
                ret);
        goto doCleanup;
    }

    ret = wolfSSL_CTX_SetDevId(ctx, 42);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_SetDevId() failed (%d)\n", ret);
        goto doCleanup;
    }

    ret = wolfSSL_CTX_GetDevId(ctx, NULL);
    if (ret != 42) {
        fprintf(stderr, "wolfSSL_CTX_GetDevId() failed (%d, expected 42)\n",
                ret);
        goto doCleanup;
    }

    wolfSSL_CTX_SetEccSignCb(ctx, test_ecc_sign_cb);

    mode = wolfSSL_CTX_set_session_cache_mode(ctx,
            SSL_SESS_CACHE_NO_AUTO_CLEAR);
    if (mode != SSL_SUCCESS) {
        fprintf(stderr, "CTX_set_session_cache_mode() failed (%lu)\n", mode);
        ret = -1;
        goto doCleanup;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new() failed\n");
        ret = -1;
        goto doCleanup;
    }

    ret = wolfSSL_CTX_GetDevId(NULL, ssl);
    if (ret != 42) {
        fprintf(stderr, "wolfSSL_CTX_GetDevId() failed (%d, expected 42)\n",
                ret);
        goto doCleanup;
    }

    ret = wolfSSL_SetDevId(ssl, INVALID_DEVID);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_SetDevId() failed (%d)\n", ret);
        goto doCleanup;
    }

    ret = wolfSSL_CTX_GetDevId(NULL, ssl);
    if (ret != INVALID_DEVID) {
        fprintf(stderr, "wolfSSL_CTX_GetDevId() failed (%d, expected %d)",
                ret, INVALID_DEVID);
        goto doCleanup;
    }

    sni = "badname";
    ret = wolfSSL_CTX_UseSNI(ctx, 0, sni, (word32)strlen(sni));
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_UseSNI() failed (%d)\n", ret);
        goto doCleanup;
    }

    ret = wolfSSL_CTX_set_timeout(ctx, 1000);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_set_timeout() failed (%d)\n", ret);
        goto doCleanup;
    }

    tcp_connect(&sfd, "localhost", port);

    ret = wolfSSL_set_fd(ssl, sfd);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_set_fd() failed (%d)\n", ret);
        goto doClose;
    }

    ret = wolfSSL_check_domain_name(ssl, "localhost");
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_check_domain_name() failed (%d)\n", ret);
        goto doClose;
    }

    ret = wolfSSL_UseALPN(ssl, alpnList, (word32)strlen(alpnList),
            WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_UseALPN() failed (%d)\n", ret);
        goto doClose;
    }

    sni = "localhost";
    ret = wolfSSL_UseSNI(ssl, 0, sni, (word32)strlen(sni));
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_UseSNI() failed (%d)\n", ret);
        goto doClose;
    }

    ret = wolfSSL_set_timeout(ssl, 300);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_set_timeout() failed (%d)\n", ret);
        goto doClose;
    }

    ret = wolfSSL_connect(ssl);
    if (ret < 0) {
        fprintf(stderr, "wolfSSL_connect failed (%d, %d)\n", ret,
                wolfSSL_get_error(ssl, 0));
        goto doClose;
    }

    cert = wolfSSL_get_peer_certificate(ssl);
    if (cert == NULL) {
        fprintf(stderr, "wolfSSL_get_peer_certificate() failed (%d)\n", ret);
        goto doClose;
    }
    ret = print_cert("wolfSSL_get_peer_certificate()", cert);
    wolfSSL_X509_free(cert);
    if (ret != 0) {
        fprintf(stderr, "print_cert() failed (%d)\n", ret);
        goto doClose;
    }

    ret = wolfSSL_write(ssl, "hi there", 9);
    if (ret != 9) {
        fprintf(stderr, "wolfSSL_write() failed (%d)\n", ret);
        goto doClose;
    }

    ret = wolfSSL_pending(ssl);
    if (ret > 0) {
        fprintf(stderr, "wolfSSL_pending() failed (%d)\n", ret);
        goto doClose;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = wolfSSL_read(ssl, buffer, sizeof(buffer));
    if (ret <= 0) {
        fprintf(stderr, "wolfSSL_read() failed (%d)\n", ret);
        goto doClose;
    }
    printf("read: %s\n", buffer);

    ret = wolfSSL_shutdown(ssl);
    if (ret == SSL_SHUTDOWN_NOT_DONE) {
        ret = wolfSSL_shutdown(ssl);
    }
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_shutdown() failed (%d)\n", ret);
        goto doClose;
    }

    if (ver != WOLFSSL_TLSV1_3) {
        session = wolfSSL_get_session(ssl);
        if (session == NULL) {
            fprintf(stderr, "wolfSSL_get_session() failed (%p)\n", session);
            goto doClose;
        }

        sessionId = wolfSSL_get_sessionID(session);
        if (sessionId == NULL) {
            fprintf(stderr, "wolfSSL_get_sessionID() failed (%p)\n", sessionId);
            goto doClose;
        }

        ret = wolfSSL_set_session(ssl, session);
        if (ret != SSL_SUCCESS) {
            fprintf(stderr, "wolfSSL_set_session() failed (%d)\n", ret);
            goto doClose;
        }
    }

    error = 0;

doClose:
    close(sfd);

doCleanup:
    wolfSSL_flush_sessions(ctx, 0);
    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);

doExit:
    return error;
}


static int
test_cert_use(void)
{
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl = NULL;
    int ret, error = -1;

    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new() failed\n");
        goto doExit;
    }

    ret = wolfSSL_CTX_use_certificate_chain_file(ctx, clientCert);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr,
                "wolfSSL_CTX_use_certificate_chain_file() failed (%d)\n", ret);
        goto doCleanup;
    }

    ret = wolfSSL_CTX_use_certificate_file(ctx, clientCert, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_use_certificate_file() failed (%d)\n",
                ret);
        goto doCleanup;
    }

    ret = wolfSSL_CTX_use_PrivateKey_file(ctx, clientKey, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_CTX_use_PrivateKey_file() failed (%d)\n", ret);
        goto doCleanup;
    }

    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        fprintf(stderr, "wolfSSL_new() failed\n");
        goto doCleanup;
    }

    ret = wolfSSL_use_certificate_chain_file(ssl, clientCert);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_use_certificate_chain_file() failed (%d)\n",
                ret);
        goto doCleanup;
    }

    ret = wolfSSL_use_certificate_file(ssl, clientCert, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_use_certificate_file() failed (%d)\n", ret);
        goto doCleanup;
    }

    ret = wolfSSL_use_PrivateKey_file(ssl, clientKey, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_use_PrivateKey_file() failed (%d)\n", ret);
        goto doCleanup;
    }

    error = 0;

doCleanup:
    if (ssl != NULL)
        wolfSSL_free(ssl);
    if (ctx != NULL)
        wolfSSL_CTX_free(ctx);

doExit:
    return error;
}


int main(int argc, char* argv[])
{
    int port = 11111;
    int ret, error = 23;

    if (argc > 1) {
        port = atoi(argv[1]);
        if (port == 0) {
            fprintf(stderr, "bad port number (%s)\n", argv[1]);
            goto doExit;
        }
    }

    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_Init() failed (%d)\n", ret);
        goto doExit;
    }

    ret = test_cert_file();
    if (ret != 0) {
        fprintf(stderr, "test_cert_file() failed\n");
        goto doCleanup;
    }

    ret = test_cert_use();
    if (ret != 0) {
        fprintf(stderr, "test_cert_use() failed\n");
        goto doCleanup;
    }

    ret = test_ecc_key();
    if (ret != 0) {
        fprintf(stderr, "test_ecc_key() failed\n");
        goto doCleanup;
    }

    ret = test_connection(2, port);
    if (ret != 0) {
        fprintf(stderr, "test_connection(TLSv1.2) failed\n");
        goto doCleanup;
    }

    ret = test_connection(3, port);
    if (ret != 0) {
        fprintf(stderr, "test_connection(TLSv1.3) failed\n");
        goto doCleanup;
    }

    error = 0;

doCleanup:
    wolfSSL_Cleanup();

doExit:
    return error;
}
EOF
) >client.c

function onExit {
    echo "On exit!"
    if test "x$_pid" != "x"
    then
        kill "$_pid"
    fi
    if test "x$_originalref" != "x"
    then
        git checkout -f "$_originalref"
    fi
}
trap onExit EXIT

echo "client: ./configure ${_confcli[@]}"
echo "server: ./configure ${_confsrv[@]}"

_originalref="$(git rev-parse --abbrev-ref HEAD)"
if test "x$_originalref" = "xHEAD"
then
    # if the original ref is just HEAD, get the current commit hash
    _originalref="$(git rev-parse HEAD | head -1)"
fi
echo "original ref: $_originalref"

echo "Building the static current version server tool"
./autogen.sh
./configure "${_confsrv[@]}"
make examples/server/server
cp examples/server/server "$PWD"

echo "Building the reference library"
git checkout "$_reftag"
# The following library version is chosen because it produces a known "older"
# library version on the dynamic library file.
sed -e '/^WOLFSSL_LIBRARY_VERSION/ s/.*/WOLFSSL_LIBRARY_VERSION=9:0:6/' -i.bak configure.ac
./autogen.sh
./configure "${_confcli[@]}"
make install

export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$PWD/local/lib"

echo "updating library link"
case "$(ls $PWD/local/lib)" in
*.dylib*)
    _oln="libwolfssl.3.dylib"
    _ln="libwolfssl.dylib"
    ;;
*.so*)
    _oln="libwolfssl.so.3"
    _ln="libwolfssl.so"
    ;;
esac

echo "Building the testing client"
gcc -o client client.c -L./local/lib -I./local/include -lwolfssl -lm

echo "Starting up the testing server"
./server -c ./certs/test/server-localhost.pem -v d -d -i -p 0 -R abi-ready &
_pid=$!

_counter=0
while test ! -s abi-ready -a "$_counter" -lt 20
do
	echo "waiting for ready file..."
	sleep 0.1
	_counter=$((_counter+1))
done

echo "======================================================================="
echo "case 1: built and run with old library (expect success)"
if ! ./client "$(cat abi-ready)"
then
    echo "case 1: Expected success, failed. Fail."
	kill $_pid
    exit 1
fi
echo "======================================================================="

echo "Vaporize local install directory"
rm -rf local

echo "======================================================================="
echo "case 2: no library (expect fail)"
if ./client "$(cat abi-ready)"
then
    echo "case 2: Expected failure, passed. Fail."
	kill $_pid
    exit 1
fi
echo "======================================================================="

echo "Installing wolfSSL commit under test"
rm -f support/wolfssl.pc
git checkout --force "$_originalref"
./autogen.sh
./configure "${_confcli[@]}"
make install

echo "======================================================================="
echo "case 3: built with old library, running with new (expect fail)"
if ./client "$(cat abi-ready)"
then
    echo "case 3: Expected failure, passed. Fail."
	kill $_pid
    exit 1
fi
echo "======================================================================="

echo "linking reference library to current library"
pushd local/lib
ln -sf "$_ln" "$_oln"
popd

echo "======================================================================="
echo "case 4: built with old library, running with new linked as old (expect success)"
if ! ./client "$(cat abi-ready)"
then
    echo "case 4: Expected success, failed. Fail."
	kill $_pid
    exit 1
fi
echo "======================================================================="

kill $_pid >/dev/null 2>&1

echo "end"
