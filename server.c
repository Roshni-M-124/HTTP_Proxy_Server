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
#define BUF_SIZE 1024
#define REQ_BUF_SIZE 8192

struct client_state {
    int fd;
    char reqbuf[REQ_BUF_SIZE];
    int req_len;
};

int make_socket_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main()
{
    int listen_fd, epfd;
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
              struct client_state *cs =malloc(sizeof(struct client_state));
              cs->fd = client_fd;
              cs->req_len = 0;
              ev.events = EPOLLIN;
              ev.data.ptr = cs;
              epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev);
              printf("New client connected: fd=%d\n", client_fd);
             }
           }
           else 
            {
                struct client_state *cs = events[i].data.ptr;
                char buf[BUF_SIZE];
                int n = recv(cs->fd, buf, sizeof buf, 0);
                if (n <= 0)
                {
                    close(cs->fd);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, cs->fd, NULL);
                    free(cs);
                    printf("Client disconnected\n");
                    continue;
                }
                if (cs->req_len + n >= REQ_BUF_SIZE)
                {
                    printf("Request too large, closing client\n");
                    close(cs->fd);
                    epoll_ctl(epfd, EPOLL_CTL_DEL, cs->fd, NULL);
                    free(cs);
                    continue;
                }
                memcpy(cs->reqbuf + cs->req_len, buf, n);
                cs->req_len += n;
                if (strstr(cs->reqbuf, "\r\n\r\n")) 
                {
                    cs->reqbuf[cs->req_len] = '\0';
                    printf("HTTP Request from client socket : %d\n",cs->fd);
                    printf("%s\n", cs->reqbuf);
                    cs->req_len = 0;
                }
            }
        }
    }
}

