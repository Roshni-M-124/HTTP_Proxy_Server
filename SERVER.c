#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#define PORT "8080"
#define BACKLOG 1024
#define MAXEVENTS 64
#define BUF_SIZE 8192
#define REQ_BUF_SIZE 16384

#define MAX_METHOD 8
#define MAX_URL 2048
#define MAX_VERSION 16
#define MAX_HOST 256
#define MAX_PATH 2048
#define MAX_PORT 8

typedef struct {
    char method[MAX_METHOD];
    char url[MAX_URL];
    char version[MAX_VERSION];
    char host[MAX_HOST];
    char port[MAX_PORT];
    char path[MAX_PATH];
} http_request_t;

struct conn {
    int fd;          
    int peer_fd;     
    int is_client;
    int is_connect;
    int established;
    char buf[REQ_BUF_SIZE];
    int buf_len;
};

int make_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int send_all(int fd, const char *buf, int len)
{
    int total = 0;
    while (total < len)
    {
        int n = send(fd, buf + total, len - total, 0);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            return -1;
        }
        total += n;
    }
    return 0;
}

int parse_http_request(const char *buf, http_request_t *req, int *is_connect)
{
    memset(req, 0, sizeof(*req));
    *is_connect = 0;
    char *reqline = strstr(buf, "\r\n");
    if (!reqline) return -1;
    char line[4096];
    int len = reqline - buf;
    memcpy(line, buf, len);
    line[len] = 0;
    if (sscanf(line, "%7s %2047s %15s",req->method, req->url, req->version) != 3)
        return -1;
    if (!strcmp(req->method, "CONNECT"))
    {
        *is_connect = 1;
        char *colon = strchr(req->url, ':');
        if (colon)
        {
            *colon = 0;
            strcpy(req->host, req->url);
            strcpy(req->port, colon + 1);
        }
        else
        {
            strcpy(req->host, req->url);
            strcpy(req->port, "443");
        }
        return 0;
    }
    strcpy(req->port, "80");
    const char *url = req->url;
    if (!strncmp(url, "http://", 7))
        url += 7;
    const char *path = strchr(url, '/');
    strcpy(req->path, path ? path : "/");
    char hostport[MAX_HOST];
    if (path)
    {
        int hlen = path - url;
        memcpy(hostport, url, hlen);
        hostport[hlen] = '\0';
    }
    else
        strcpy(hostport, url);
    char *colon = strchr(hostport, ':');
    if (colon)
    {
        *colon = '\0';
        strcpy(req->host, hostport);
        strcpy(req->port, colon + 1);
    }
    else
        strcpy(req->host, hostport);
    return 0;
}

int connect_to_server(const char *host, const char *port)
{
    struct addrinfo hints, *res, *p;
    int yes = 1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    for (p = res; p != NULL; p = p->ai_next)
    {
        int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) 
          continue;
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
        {
            make_socket_nonblocking(fd);
            freeaddrinfo(res);
            return fd;
        }
        close(fd);
    }
    freeaddrinfo(res);
    return -1;
}

int main()
{
    int listen_fd, epfd;
    struct epoll_event ev, events[MAXEVENTS];
    struct addrinfo hints, *ai;
    int yes = 1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    getaddrinfo(NULL, PORT, &hints, &ai);
    listen_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    make_socket_nonblocking(listen_fd);
    bind(listen_fd, ai->ai_addr, ai->ai_addrlen);
    listen(listen_fd, BACKLOG);
    freeaddrinfo(ai);
    
    epfd = epoll_create1(0);
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);
    printf("Proxy listening on %s\n", PORT);
    while (1)
    {
        int nfds = epoll_wait(epfd, events, MAXEVENTS, -1);
        for (int i = 0; i < nfds; i++)
        {
            if (events[i].data.fd == listen_fd)
            {
                int cfd = accept(listen_fd, NULL, NULL);
                make_socket_nonblocking(cfd);
                struct conn *c = calloc(1, sizeof(*c));
                c->fd = cfd;
                c->peer_fd = -1;
                c->is_client = 1;
                ev.events = EPOLLIN;
                ev.data.ptr = c;
                epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev);
                continue;
            }
            
            struct conn *c = events[i].data.ptr;
            char buf[BUF_SIZE];
            if (c->established)
            {
              int n = recv(c->fd, buf, sizeof(buf), 0);
              if (n <= 0)
                goto cleanup;

              send_all(c->peer_fd, buf, n);
              continue;
            }
            int n = recv(c->fd, buf, sizeof(buf), 0);
            if (n <= 0)
              goto cleanup;
            if (!c->established)
            {
              memcpy(c->buf + c->buf_len, buf, n);
              c->buf_len += n;
              if (!strstr(c->buf, "\r\n\r\n"))
                continue;
              http_request_t req;
              if (parse_http_request(c->buf, &req, &c->is_connect) < 0)
                goto cleanup;
              int sfd = connect_to_server(req.host, req.port);
              if (sfd < 0)
                goto cleanup;
              struct conn *s = calloc(1, sizeof(*s));
              s->fd = sfd;
              s->peer_fd = c->fd;
              s->is_client = 0;
              s->established = 0;
              c->peer_fd = sfd;
              c->established = 0;
              ev.events = EPOLLIN;
              ev.data.ptr = s;
              epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
              if (c->is_connect)
              {
                send_all(c->fd, "HTTP/1.1 200 Connection Established\r\n\r\n", 39);
                c->established = 1;
                s->established = 1;
              }
              else
              {
                char *first_line_end = strstr(c->buf, "\r\n");
                char *headers_start = first_line_end + 2;
                char new_req[REQ_BUF_SIZE];
                int new_len = snprintf(new_req, sizeof(new_req), "%s %s %s\r\n", req.method, req.path, req.version);
                int remain = c->buf_len - (headers_start - c->buf);
                memcpy(new_req + new_len, headers_start, remain);
                new_len += remain;
                send_all(s->fd, new_req, new_len);
                c->established = 1;
                s->established = 1;
              }
              c->buf_len = 0;
            }
            else
            {
              send_all(c->peer_fd, buf, n);
            }
            continue;

cleanup:
          epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
          close(c->fd);
          if (c->peer_fd != -1)
          {
            epoll_ctl(epfd, EPOLL_CTL_DEL, c->peer_fd, NULL);
            close(c->peer_fd);
          }
          free(c);
        }
      }
}

