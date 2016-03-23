#include "sysutil.h"

/**
 * tcp_server - 启动tcp服务器
 * @host: 服务器IP地址或者服务器主机名
 * @port: 服务器端口号
 * 成功返回监听套接字
 */
int tcp_server(const char *host, unsigned short port)
{
    int listenfd = -1;
    if ((listenfd == socket(AF_INET, SOCK_STREAM, 0)) < 0)
        err_sys("tcp_server");

    struct sockaddr_in servaddr;
    bzero((void *)&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    if (host != NULL)
    {
        if (inet_aton(host, &servaddr.sin_addr) == 0)
        {
            struct hostent *hp;
            if ((hp = gethostbyname(host)) == NULL)
                err_sys("gethostbyname");

            servaddr.sin_addr = *(struct in_addr*)hp->h_addr;
        }
    }
    else
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    servaddr.sin_port = htons(port);

    int on = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on)) < 0)
        err_sys("gethostbyname");

    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        err_sys("bind");

    if (listen(listenfd, LISTENQ) < 0)
        err_sys("listen");

    return listenfd;
}

int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
    int ret;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    if (wait_seconds > 0)
    {
        fd_set accept_fdset;
        struct timeval timeout;
        FD_ZERO(&accept_fdset);
        FD_SET(fd, &accept_fdset);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;
        do
        {
            ret = select(fd + 1, &accept_fdset, NULL, NULL, &timeout);
        } while (ret < 0 && errno == EINTR);
        if (ret == -1)
        {
            return -1;
        }
        else if (ret == 0)
        {
            errno = ETIMEDOUT;
            return -1;
        }
    }

    if (addr != NULL)
        ret = accept(fd, (struct sockaddr*)addr, &addrlen);
    else
        ret = accept(fd, NULL, NULL);

    return ret;
}
