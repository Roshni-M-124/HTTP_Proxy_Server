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
    struct conn *peer;
    int is_connect;
    int established;
    char inbuf[REQ_BUF_SIZE];
    int in_len;
    char outbuf[REQ_BUF_SIZE];
    int out_len;
    int out_sent;
    int cleaned;
};

int make_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int parse_http_request(const char *buf, http_request_t *req, int *is_connect)
{
    memset(req, 0, sizeof(*req));
    *is_connect = 0;
    char *reqline = strstr(buf, "\r\n");
    if (!reqline)
        return -1;
    char line[4096];
    int len = reqline - buf;
    memcpy(line, buf, len);
    line[len] = 0;
    if (sscanf(line, "%7s %2047s %15s", req->method, req->url, req->version) != 3)
        return -1;
    if (!strcmp(req->method, "CONNECT"))
    {
        *is_connect = 1;
        char *colon = strchr(req->url, ':');
        if (colon) {
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
    {
        strcpy(hostport, url);
    }
    char *colon = strchr(hostport, ':');
    if (colon)
    {
        *colon = '\0';
        strcpy(req->host, hostport);
        strcpy(req->port, colon + 1);
    } 
    else
    {
        strcpy(req->host, hostport);
    }
    printf("Request: %s %s \n", req->method, req->url);
    return 0;
}

int connect_to_server(const char *host, const char *port)
{
    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    for (p = res; p != NULL; p = p->ai_next)
    {
        int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) 
            continue;
        make_socket_nonblocking(fd);
        int r;
        r = connect(fd, p->ai_addr, p->ai_addrlen);
        if (r == 0 || errno == EINPROGRESS)
        {
            freeaddrinfo(res);
            return fd;
        }
        close(fd);
    }
    freeaddrinfo(res);
    return -1;
}

void send_data(int epfd, struct conn *c, const char *data, int len)
{
    if (!c || len <= 0) 
        return;
    if (c->out_len + len > REQ_BUF_SIZE)
        return;
    memcpy(c->outbuf + c->out_len, data, len);
    c->out_len += len;
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
    ev.data.ptr = c;
    epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
}

void cleanup_conn(int epfd, struct conn *c)
{
    if (!c || c->cleaned)
        return;
    c->cleaned = 1;
    epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
    close(c->fd);
    if (c->peer) 
    {
        c->peer->peer = NULL;
        c->peer = NULL;
    }
    free(c);
}

int main()
{
    int listen_fd, epfd;
    struct epoll_event ev, events[MAXEVENTS];
    struct addrinfo hints, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    getaddrinfo(NULL, PORT, &hints, &ai);
    listen_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    int yes = 1;
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
                ev.events = EPOLLIN | EPOLLRDHUP;
                ev.data.ptr = c;
                epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &ev);
                continue;
            }
            struct conn *c = events[i].data.ptr;
            if (events[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR))
            {
                cleanup_conn(epfd, c);
                continue;
            }
            if (events[i].events & EPOLLOUT)
            {
                if (!c->established) 
                {
                    c->established = 1;
                    if (c->peer && c->peer->in_len > 0) 
                    {
                        send_data(epfd, c, c->peer->inbuf, c->peer->in_len);
                        c->peer->in_len = 0;
                    }
                    struct epoll_event ev2;
                    ev2.events = EPOLLIN | EPOLLRDHUP;
                    ev2.data.ptr = c;
                    epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev2);
                }
                else
                {
                    while (c->out_sent < c->out_len)
                    {
                        int n = send(c->fd, c->outbuf + c->out_sent, c->out_len - c->out_sent, 0);
                        if (n < 0)
                        {
                            if (errno == EAGAIN || errno == EWOULDBLOCK)
                                break;
                            cleanup_conn(epfd, c);
                              continue;
                        }
                        c->out_sent += n;
                    }   
                    if (c->out_sent == c->out_len)
                    {
                        c->out_len = 0;
                        c->out_sent = 0;
                        ev.events = EPOLLIN | EPOLLRDHUP;
                        ev.data.ptr = c;
                        epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
                    }
                }
            }
            if (events[i].events & EPOLLIN)
            {
                char buf[BUF_SIZE];
                int n = recv(c->fd, buf, sizeof(buf), 0);
                if (n <= 0)
                {
                    cleanup_conn(epfd, c);
                    continue;
                }
                if (c->established)
                {
                    send_data(epfd, c->peer, buf, n);
                }
                else
                {
                    if (c->in_len + n > REQ_BUF_SIZE)
                    {
                        cleanup_conn(epfd, c);
                        continue;
                    }
                    memcpy(c->inbuf + c->in_len, buf, n);
                    c->in_len += n;
                    if (!strstr(c->inbuf, "\r\n\r\n"))
                        continue;
                    http_request_t req;
                    if (parse_http_request(c->inbuf, &req, &c->is_connect) < 0)
                    {
                        cleanup_conn(epfd, c);
                        continue;
                    }
                    int sfd = connect_to_server(req.host, req.port);
                    if (sfd < 0)
                    {
                        cleanup_conn(epfd, c);
                        continue;
                    }
                    struct conn *s = calloc(1, sizeof(*s));
                    s->fd = sfd;
                    c->peer = s;
                    s->peer = c;
                    ev.events = EPOLLIN | EPOLLRDHUP|EPOLLOUT;
                    ev.data.ptr = s;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
                    if (c->is_connect)
                    {
                        send_data(epfd, c, "HTTP/1.1 200 Connection Established\r\n\r\n", 39);
                        printf("HTTPS tunnel established to %s:%s\n", req.host, req.port);
                    }
                    else
                    {
                        char *first_line_end = strstr(c->inbuf, "\r\n");
                        char *headers_start = first_line_end + 2;
                        char new_req[REQ_BUF_SIZE];
                        int new_len = snprintf(new_req, sizeof(new_req), "%s %s %s\r\n", req.method, req.path, req.version);
                        int remain = c->in_len - (headers_start - c->inbuf);
                        memcpy(new_req + new_len, headers_start, remain);
                        new_len += remain;
                        send_data(epfd, s, new_req, new_len);
                    }
                    c->established = 1;
                    s->established = 1;
                    c->in_len = 0;
                }
            }
        }
    }
    return 0;
}

