#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUF_SIZE 8192

typedef struct {
    char scheme[8];
    char host[256];
    int port;
    char path[1024];
} url_t;

void parse_url(const char *url, url_t *u) 
{
    memset(u, 0, sizeof(*u));
    if (strncmp(url, "https://", 8) == 0)
    {
        strcpy(u->scheme, "https");
        u->port = 443;
        url += 8;
    } 
    else
    {
        strcpy(u->scheme, "http");
        u->port = 80;
        if (strncmp(url, "http://", 7) == 0)
            url += 7;
    }
    const char *slash = strchr(url, '/');
    if (slash) 
    {
        strncpy(u->host, url, slash - url);
        strcpy(u->path, slash);
    }
    else
    {
        strcpy(u->host, url);
        strcpy(u->path, "/");
    }
}

int tcp_connect(const char *host, int port) 
{
    struct addrinfo hints, *res,*p;
    char portstr[16];
    int sock;
    snprintf(portstr, sizeof(portstr), "%d", port);
    memset(&hints, 0, sizeof hints);
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0)
        return -1;
    for (p = res; p != NULL; p = p->ai_next)
    {
        int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) 
          continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
        {
            freeaddrinfo(res);
            return fd;
        }
        close(fd);
    }
    freeaddrinfo(res);
    return -1;
}

SSL *tls_wrap(int sock, const char *hostname, SSL_CTX **out_ctx) 
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return NULL;
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
    {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_set_tlsext_host_name(ssl, hostname);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }
    *out_ctx = ctx;
    return ssl;
}

int main(int argc, char *argv[])
{
    if (argc != 5) 
    {
        fprintf(stderr,"Usage: %s METHOD URL PROXY_HOST PROXY_PORT\n", argv[0]);
        return 1;
    }
    const char *method = argv[1];
    const char *urlstr = argv[2];
    const char *proxy_host = argv[3];
    int proxy_port = atoi(argv[4]);
    url_t url;
    parse_url(urlstr, &url);
    int is_https = strcmp(url.scheme, "https") == 0;
    int sock = tcp_connect(proxy_host, proxy_port);
    if (sock < 0)
    {
        perror("connect");
        return 1;
    }
    SSL *ssl = NULL;
    SSL_CTX *ssl_ctx = NULL;
    if (is_https) 
    {
        char connect_req[1024];
        int len = snprintf(connect_req, sizeof(connect_req),"CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n",url.host, url.port, url.host, url.port);
        send(sock, connect_req, len, 0);
        char resp[BUF_SIZE];
        int n = recv(sock, resp, sizeof(resp) - 1, 0);
        if (n <= 0 || strstr(resp, "200") == NULL) 
        {
            fprintf(stderr, "CONNECT failed\n");
            return 1;
        }
        SSL_library_init();
        ssl = tls_wrap(sock, url.host, &ssl_ctx);
        if (!ssl)
        {
            fprintf(stderr, "TLS failed\n");
            return 1;
        }
    }
    char request[BUF_SIZE];
    if (is_https) 
    {
        snprintf(request, sizeof(request),"%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",method,url.path,url.host);
        SSL_write(ssl, request, strlen(request));
    } 
    else
    {
        snprintf(request, sizeof(request),"%s http://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
        method, url.host, url.path, url.host);
        send(sock, request, strlen(request), 0);
    }
    char buf[BUF_SIZE];
    int n;
    while (1) 
    {
        if (is_https)
            n = SSL_read(ssl, buf, sizeof(buf) - 1);
        else
            n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        printf("%s", buf);
    }
    if (ssl)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ssl_ctx)
        SSL_CTX_free(ssl_ctx);
    close(sock);
    return 0;
}

