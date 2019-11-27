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


static inline void
err_sys(const char* msg)
{
    printf("wolfSSL error: %s\n", msg);

    exit(EXIT_FAILURE);
}

static inline void build_addr(SOCKADDR_IN_T* addr, const char* peer,
                              unsigned short port)
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
            printf("no ipv6 getaddrinfo, loopback only tests/examples\n");
            addr->sin6_addr = in6addr_loopback;
        #endif
    }
#endif
}

static inline void tcp_socket(SOCKET_T* sockfd)
{
    *sockfd = socket(AF_INET_V, SOCK_STREAM, IPPROTO_TCP);

    if(*sockfd < 0) {
        err_sys("socket failed\n");
    }

    signal(SIGPIPE, SIG_IGN);
}

static inline void tcp_connect(SOCKET_T* sockfd, const char* ip,
                               unsigned short port)
{
    SOCKADDR_IN_T addr;
    build_addr(&addr, ip, port);
    tcp_socket(sockfd);

    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_sys("tcp connect failed");
}


static int dumpTime(const char* desc, const unsigned char* time)
{
    int i, length;
    unsigned char flatTime[64];
    unsigned char type;

    type = time[0];
    length = (int)time[1];

    memcpy(flatTime, &time[2], length);
    flatTime[length] = '\0';

    printf("  %12s: (%u) %s\n", desc, type, flatTime);

    return 0;
}


static int dumpCert(const char* desc, WOLFSSL_X509* cert)
{
    WOLFSSL_X509_NAME* xName;
    const unsigned char* xTime;
    char* nameP;
    char name[256];
    unsigned char length, type;

    printf("%s\n", desc);
    xName = wolfSSL_X509_get_issuer_name(cert);
    nameP = wolfSSL_X509_NAME_oneline(xName, name, (int)sizeof(name));
    printf("  %12s: %s\n", "issuer name", nameP);

    xName = wolfSSL_X509_get_subject_name(cert);
    nameP = wolfSSL_X509_NAME_oneline(xName, name, (int)sizeof(name));
    printf("  %12s: %s\n", "subject name", nameP);

    do {
        nameP = wolfSSL_X509_get_next_altname(cert);
        if (nameP != NULL) {
            printf("%12s: %s\n", "altname", nameP);
        }
    } while (nameP != NULL);

    xTime = wolfSSL_X509_notBefore(cert);
    dumpTime("notBefore", xTime);

    xTime = wolfSSL_X509_notAfter(cert);
    dumpTime("notAfter", xTime);

    return 0;
}


int testKey(void)
{
    WC_RNG* rng = NULL;
    ecc_key* ecc = NULL;
    byte nonce[32];
    byte digest[32];
    byte sig[72];
    int ret = 0;
    word32 digestSz = sizeof(digest), sigSz = sizeof(sig);

    memset(nonce, 0, sizeof(nonce));

    rng = wc_rng_new(nonce, (word32)sizeof(nonce), NULL);
    if (rng == NULL) {
        printf("Couldn't get a random number generator.\n");
        goto doExit;
    }

    wc_RNG_GenerateBlock(rng, digest, digestSz);

    ecc = wc_ecc_key_new(NULL);
    if (ecc == NULL) {
        printf("Couldn't allocate ECC key.\n");
        goto doExit;
    }

    ret = wc_ecc_init_ex(ecc, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("Couldn't initialize ECC key. (%d)\n", ret);
        goto doExit;
    }
    ret = wc_ecc_make_key_ex(rng, 32, ecc, ECC_SECP256R1);
    if (ret != 0) {
        printf("Couldn't generate ECC key. (%d)\n", ret);
        goto doExit;
    }
    ret = wc_ecc_sign_hash(digest, digestSz, sig, &sigSz, rng, ecc);
    if (ret != 0) {
        printf("Couldn't sign hash. (%d)\n", ret);
        goto doExit;
    }

doExit:
    if (ecc != NULL) {
        wc_ecc_free(ecc);
        wc_ecc_key_free(ecc);
    }
    if (rng != NULL)
        wc_rng_free(rng);

    return ret;
}


int main(int argc, char* argv[])
{
    WOLFSSL_X509* cert;
    int port = 11111;
    int ret;

    if (argc > 1) {
        port = atoi(argv[1]);
        if (port == 0) {
            printf("bad port number (%s)\n", argv[1]);
            return 1;
        }
    }

    printf("hello\n");

    ret = wolfSSL_Init();
    if (ret != SSL_SUCCESS)
        printf("init = %d\n", ret);

    cert = wolfSSL_X509_load_certificate_file("./certs/server-cert.pem",
            SSL_FILETYPE_PEM);
    dumpCert("wolfSSL_X509_load_certificate_file()", cert);
    wolfSSL_X509_free(cert);

    testKey();

    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (ctx) printf("got a good ctx\n");

    ret = wolfSSL_CTX_load_verify_locations(ctx, "./certs/ca-cert.pem", 0);
    printf("load verify ret = %d\n", ret);

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (ssl) printf("got a good ssl\n");

    SOCKET_T sfd;

    tcp_connect(&sfd, "localhost", port);

    wolfSSL_set_fd(ssl, sfd);

    ret = wolfSSL_connect(ssl);

    printf("ssl connect ret = %d\n", ret);
    if (ret < 0) {
        int err = wolfSSL_get_error(ssl, 0);
        printf("err = %d\n", err);
    }

    cert = wolfSSL_get_peer_certificate(ssl);
    dumpCert("wolfSSL_get_peer_certificate()", cert);
    wolfSSL_X509_free(cert);

    ret = wolfSSL_write(ssl, "hi there", 9);
    printf("write ret = %d\n", ret);

    char buffer[128];
    memset(buffer, 0, sizeof(buffer));
    ret = wolfSSL_read(ssl, buffer, sizeof(buffer));
    printf("read ret = %d\n", ret);
    printf("read %s\n", buffer);

    printf("bye\n");

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    printf("bye\n");

    return 0;
}
