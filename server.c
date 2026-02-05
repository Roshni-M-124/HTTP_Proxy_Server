#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#define PORT "8080"
#define BACKLOG 1000
#define MAXEVENTS 64
#define BUF_SIZE 8192
#define REQ_BUF_SIZE 8192

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
    int  is_connect;
} http_request_t;

struct client{
    int client_fd;
    int server_fd;
    char reqbuf[REQ_BUF_SIZE];
    int req_len;
};

int make_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int parse_http_request(const char *reqbuf, http_request_t *req)
{
  memset(req, 0, sizeof(*req));
  
  //Extract request line 
  
  char *line_end = strstr(reqbuf, "\r\n");
  if (!line_end)
    return -1;
  char request_line[4096];
  int len = line_end - reqbuf;
  strncpy(request_line, reqbuf, len);
  request_line[len] = '\0';
  if (sscanf(request_line, "%7s %2047s %15s",req->method, req->url, req->version) != 3)
    return -1;
    
  //HTTPS 
  
  if (strcmp(req->method, "CONNECT") == 0)
  {
    req->is_connect = 1;
    char hostport[MAX_HOST];
    strncpy(hostport, req->url, sizeof(hostport) - 1);
    char *colon = strchr(hostport, ':');
    if (colon)
    {
      *colon = '\0';
      strncpy(req->host, hostport, MAX_HOST - 1);
      strncpy(req->port, colon + 1, MAX_PORT - 1);
    } 
    else 
    {
      strncpy(req->host, hostport, MAX_HOST - 1);
      strcpy(req->port, "443");
    }
    strcpy(req->path, "");
    return 0;
  }

    // HTTP
  req->is_connect = 0;
  strcpy(req->port, "80");
  const char *url = req->url;
  if (strncmp(url, "http://", 7) == 0)
    url += 7;
  const char *path_start = strchr(url, '/');
  if (path_start) 
  {
    strncpy(req->path, path_start, MAX_PATH - 1);
  } 
  else
  {
    strcpy(req->path, "/");
  }
  char hostport[MAX_HOST];
  if (path_start)
  {
    int hlen = path_start - url;
    strncpy(hostport, url, hlen);
    hostport[hlen] = '\0';
  }
  else
  {
    strncpy(hostport, url, sizeof(hostport) - 1);
  }
  char *colon = strchr(hostport, ':');
  if (colon) 
  {
    *colon = '\0';
    strncpy(req->host, hostport, MAX_HOST - 1);
    strncpy(req->port, colon + 1, MAX_PORT - 1);
  }
  else
  {
    strncpy(req->host, hostport, MAX_HOST - 1);
  }
  if (strlen(req->host) == 0)
  {
    char *h = strstr(reqbuf, "\r\nHost:");
    if (h)
    {
      h += 7;
      while (*h == ' ') 
        h++;
      char *end = strstr(h, "\r\n");
      if (end)
      {
        int l = end - h;
        strncpy(req->host, h, l);
        req->host[l] = '\0';
      }
    }
  }
  return 0;
}

int connect_to_server(struct client *c, http_request_t *req)
{
  struct addrinfo hints, *res, *p;
  int server_fd;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(req->host, req->port, &hints, &res) != 0)
  {
    perror("getaddrinfo");
    return -1;
  }
  for (p = res; p != NULL; p = p->ai_next)
  {
    server_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (server_fd < 0)
      continue;
    if (connect(server_fd, p->ai_addr, p->ai_addrlen) == 0)
      break;
    close(server_fd);
  }
  freeaddrinfo(res);
  if (p == NULL)
    return -1;
  c->server_fd = server_fd;
  return 0;
}

int main()
{
    int listen_fd, epfd,rv;
    struct addrinfo hints, *servinfo, *p;
    struct epoll_event ev, events[MAXEVENTS];
    int yes = 1;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if((rv=getaddrinfo(NULL,PORT,&hints,&servinfo))==-1)
    {
      fprintf(stderr, "server: %s\n", gai_strerror(rv));
      exit(1);
    }
    for(p = servinfo; p!= NULL; p = p->ai_next)
    {
      if((listen_fd=socket(p->ai_family, p->ai_socktype, p->ai_protocol))<0)
      {
        continue;
      }
      if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes,sizeof(int)) == -1)
      {
        perror("setsockopt");
        exit(1);
      }
      fcntl(listen_fd, F_SETFL, O_NONBLOCK);
      if((bind(listen_fd,p->ai_addr, p->ai_addrlen))<0)
      {
        close(listen_fd);
        continue;
      }
      break;
    } 
    if(p==NULL)
    {
      fprintf(stderr, "error getting listening socket\n");
      exit(2);
    } 
    freeaddrinfo(servinfo);
    if((listen(listen_fd,BACKLOG))==-1)
    {
      fprintf(stderr, "error getting listening socket\n");
      exit(3);
    }
    epfd = epoll_create1(0);
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev);
    printf("Proxy server listening on port %s\n", PORT);
    while (1)
    {
      int nfds = epoll_wait(epfd, events, MAXEVENTS, -1);
      for (int i = 0; i < nfds; i++)
      {
        if (events[i].data.fd == listen_fd)
        {
          while (1) 
          {
            struct sockaddr_storage addr;
            socklen_t len = sizeof addr;
            int client_fd = accept(listen_fd,(struct sockaddr *)&addr, &len);
            if (client_fd < 0)
            {
              if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
              perror("accept");
              break;
            }
            make_socket_nonblocking(client_fd);
            struct client *c =malloc(sizeof(struct client));
            c->client_fd = client_fd;
            c->req_len = 0;
            ev.events = EPOLLIN;
            ev.data.ptr = c;
            epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev);
            printf("New client connected: fd=%d\n", client_fd);
          } 
      } 
      else 
      {
        struct client *c = events[i].data.ptr;
        char buf[BUF_SIZE];
        int n = recv(c->client_fd, buf, sizeof buf, 0);
        if (n <= 0)
        {
          close(c->client_fd);
          epoll_ctl(epfd, EPOLL_CTL_DEL, c->client_fd, NULL);
          free(c);
          printf("Client disconnected\n");
          continue;
        }
        if(c->req_len + n >= REQ_BUF_SIZE)
        {
          printf("Request too large, closing client\n");
          close(c->client_fd);
          epoll_ctl(epfd, EPOLL_CTL_DEL, c->client_fd, NULL);
          free(c);
          continue;
        }
        memcpy(c->reqbuf + c->req_len, buf, n);
        c->req_len += n;
        if (strstr(c->reqbuf, "\r\n\r\n")) 
        {
          c->reqbuf[c->req_len] = '\0';
          printf("HTTP Request from client socket : %d\n",c->client_fd);
          printf("%s\n", c->reqbuf);
          c->req_len = 0;
          http_request_t req;
          if (parse_http_request(c->reqbuf, &req) == 0) 
          {
            printf("Method : %s\n", req.method);
            printf("URL    : %s\n", req.url);
            printf("Version: %s\n", req.version);
            printf("Host   : %s\n", req.host);
            printf("Port   : %s\n", req.port);
            printf("Path   : %s\n", req.path);
            printf("CONNECT: %d\n\n", req.is_connect);
            if (connect_to_server(c, &req) == 0)
            {
              printf("Connected to server %s:%s on socket %d\n\n",req.host, req.port, c->server_fd);
            }
            else
            {
              printf("Failed to connect to server %s:%s\n\n",req.host, req.port);
            }
          }
          else
          {
            printf("Failed to parse request\n");
          }
        }
      }
    }
  }
  return 0;
}

