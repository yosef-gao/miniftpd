#include "sysutil.h"
#include "tunable.h"

static struct cmsghdr *cmptr = NULL;
#define CONTROLLEN CMSG_LEN(sizeof(int))
/**
 * tcp_server - 启动tcp服务器
 * @host: 服务器IP地址或者服务器主机名
 * @port: 服务器端口号
 * 成功返回监听套接字
 */
int tcp_server(const char *host, unsigned short port)
{
    int listenfd;
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
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
        err_sys("setsockopt");

    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
        err_sys("bind");

    if (listen(listenfd, LISTENQ) < 0)
        err_sys("listen");

    return listenfd;
}

int getlocalip(char* ip_str)
{
    char hname[128];
    struct hostent *hent;

    if (gethostname(hname, sizeof(hname)) < 0)
        return -1;

    hent = gethostbyname(hname);
    if (hent == NULL)
        return -1;

    printf("hostname: %s\naddress list: ", hent->h_name);

    int i;
    for(i = 0; hent->h_addr_list[i] != NULL; i++) {
        printf("%s\t", inet_ntoa(*(struct in_addr*)(hent->h_addr_list[i])));
    }
    return 0;
}

int tcp_client(struct sockaddr_in *servaddr, unsigned short port)
{
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        err_sys("tcp_client");

    struct sockaddr_in localaddr;
    bzero(&localaddr, sizeof(localaddr));
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localaddr.sin_port = htons(port);

    int on = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on)) < 0)
        err_sys("setsockopt");

    if (bind(sockfd, (struct sockaddr*)&localaddr, sizeof(localaddr)) < 0)
        err_sys("bind");

    if (connect_timeout(sockfd, servaddr, tunable_connect_timeout) < 0)
        err_sys("connect_timeout");

    return sockfd;
}

int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
    if (addr == NULL)
        return -1;

    int ret;
    socklen_t addrlen = sizeof(struct sockaddr_in);

    if (wait_seconds > 0)
    {
        fd_set connect_fdset;
        struct timeval timeout;
        FD_ZERO(&connect_fdset);
        FD_SET(fd, &connect_fdset);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;
        do
        {
            ret = select(fd + 1, &connect_fdset, NULL, NULL, &timeout);
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

    ret = connect(fd, (struct sockaddr*)addr, addrlen);

    return ret;
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

ssize_t readn(int fd, void *buff, size_t n)
{
    size_t nleft;
    ssize_t nread;
    char *ptr;

    ptr = buff;
    nleft = n;
    while (nleft > 0)
    {
        if ((nread = read(fd, ptr, nleft)) < 0)
        {
            if (errno == EINTR)
                nread = 0; /* and call read() again */
            else
                return (-1);
        }
        else if (nread == 0)
            break; /* EOF */

        nleft -= nread;
        ptr += nread;
    }
    return (n - nleft); /* return >= 0 */
}

ssize_t writen(int fd, const void *buff, size_t n)
{
    size_t nleft;
    ssize_t nwritten;
    const char *ptr;

    ptr = buff;
    nleft = n;
    while (nleft > 0)
    {
        if ((nwritten = write(fd, ptr, nleft)) <= 0)
        {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0; /* and call write() again */
            else
                return (-1); /* error */
        }
        nleft -= nwritten;
        ptr += nwritten;
    }
    return (n);
}

ssize_t readline(int fd, void *buff, size_t maxlen)
{
    ssize_t n, rc;
    char c, *ptr;

    ptr = buff;
    for (n = 1; n < maxlen; ++n)
    {
again:
        if ((rc = read(fd, &c, 1)) == 1)
        {
            *ptr++ = c;
            if (c == '\n')
                break; /* newline is stored, like fgets()*/
        }
        else if (rc == 0)
        {
            *ptr = 0;
            return (n - 1); /* EOF, n - 1 bytes were read */
        }
        else
        {
            if (errno == EINTR)
                goto again;
            return (-1); /* error, errno set by read() */
        }
    }
    *ptr = 0;
    return (n);
}

int send_fd(int fd, int fd_to_send)
{
    struct iovec iov[1];
    struct msghdr msg;
    char buf[2];

    iov[0].iov_base = buf;
    iov[0].iov_len = 2;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    if (fd_to_send < 0)
    {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
        buf[1] = -fd_to_send; /* nonzero status means error */
        if (buf[1] == 0)
            buf[1] = 1;
    }
    else
    {
        if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
            return -1;
        cmptr->cmsg_level = SOL_SOCKET;
        cmptr->cmsg_type = SCM_RIGHTS;
        cmptr->cmsg_len = CONTROLLEN;
        msg.msg_control = cmptr;
        msg.msg_controllen = CONTROLLEN;
        *(int *)CMSG_DATA(cmptr) = fd_to_send; /* th fd to pass */
        buf[1] = 0; /* zero status means OK */
    }

    buf[0] = 0;
    if (sendmsg(fd, &msg, 0) != 2)
        return (-1);
    return (0);
}

int send_err(int fd, int errcode, const char *msg)
{
    int n;
    if ((n = strlen(msg)) > 0)
    {
        if (writen(fd, msg, n) != n)
            return (-1);
    }

    if (errcode >= 0)
        errcode = -1;

    if (send_fd(fd, errcode) < 0)
        return (-1);
    return (0);
}

int recv_fd(int fd, ssize_t (*userfunc)(int , const void *, size_t))
{
    int newfd, nr, status;
    char *ptr;
    char buf[MAXLINE];
    struct iovec iov[1];
    struct msghdr msg;

    status = -1;
    for (;;)
    {
        iov[0].iov_base = buf;
        iov[0].iov_len = sizeof(buf);
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
        if (cmptr == NULL && (cmptr = malloc(CONTROLLEN)) == NULL)
            return (-1);
        msg.msg_control = cmptr;
        msg.msg_controllen = CONTROLLEN;
        if ((nr = recvmsg(fd, &msg, 0)) < 0)
        {
            err_ret("recvmsg error");
            return (-1);
        }
        else if (nr == 0)
        {
            err_ret("connection closed by server");
            return (-1);
        }

        for (ptr = buf; ptr < &buf[nr]; )
        {
            if (*ptr++ == 0)
            {
                if (ptr != &buf[nr-1])
                    err_dump("message format error");
                status = *ptr & 0xFF; /* prevent sign extension */
                if (status == 0)
                {
                    if (msg.msg_controllen < CONTROLLEN)
                        err_dump("status = 0 but no fd");
                    newfd = *(int *)CMSG_DATA(cmptr);
                }
                else
                {
                    newfd = -status;
                }
                nr -= 2;
            }
        }
        if (nr > 0 && (*userfunc)(STDERR_FILENO, buf, nr) != nr)
            return (-1);
        if (status >= 0) /* final data has arrived */
            return (newfd);
    }
}

void statbuf_get_perms(struct stat *sbuf, char *perms)
{
    mode_t mode = sbuf->st_mode;
    switch (mode & S_IFMT)
    {
        case S_IFREG:
            perms[0] = '-';
            break;
        case S_IFDIR:
            perms[0] = 'd';
            break;
        case S_IFLNK:
            perms[0] = 'l';
            break;
        case S_IFIFO:
            perms[0] = 'p';
            break;
        case S_IFSOCK:
            perms[0] = 's';
            break;
        case S_IFCHR:
            perms[0] = 'c';
            break;
        case S_IFBLK:
            perms[0] = 'b';
            break;
    }

    if (mode & S_IRUSR)
    {
        perms[1] = 'r';
    }
    if (mode & S_IWUSR)
    {
        perms[2] = 'w';
    }
    if (mode & S_IXUSR)
    {
        perms[3] = 'x';
    }
    if (mode & S_IRGRP)
    {
        perms[4] = 'r';
    }
    if (mode & S_IWGRP)
    {
        perms[5] = 'w';
    }
    if (mode & S_IXGRP)
    {
        perms[6] = 'x';
    }
    if (mode & S_IROTH)
    {
        perms[7] = 'r';
    }
    if (mode & S_IWOTH)
    {
        perms[8] = 'w';
    }
    if (mode & S_IXOTH)
    {
        perms[9] = 'x';
    }
    if (mode & S_ISUID)
    {
        perms[3] = (perms[3] == 'x' ? 's' : 'S');
    }
    if (mode & S_ISGID)
    {
        perms[6] = (perms[6] == 'x' ? 's' : 'S');
    }
    if (mode & S_ISVTX)
    {
        perms[9] = (perms[9] == 'x' ? 't' : 'T');
    }
}

void statebuf_get_datetime(struct stat *sbuf, char *datebuf, size_t buf_size)
{
    const char *p_date_format = "%b %e %H:%M";
    time_t current_time;
    time(&current_time);

    if (sbuf->st_mtime > current_time || (current_time - sbuf->st_mtime) > 182*24*60*60) // half year
    {
        p_date_format = "%b %e %Y";
    }

    struct tm *p_tm = localtime(&sbuf->st_mtime);
    strftime(datebuf, buf_size, p_date_format, p_tm);
}

static int lock_internal(int fd, int lock_type)
{
    int ret;

    struct flock the_lock;
    memset(&the_lock, 0, sizeof(the_lock));
    the_lock.l_type = lock_type; 
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0; // all the file

    do
    {
        ret = fcntl(fd, F_SETLKW, &the_lock);
    } while (ret < 0 && errno == EINTR);

    return ret;

}

int lock_file_read(int fd)
{
    return lock_internal(fd, F_RDLCK);
}

int lock_file_write(int fd)
{
    return lock_internal(fd, F_WRLCK);
}

int unlock_file(int fd)
{
   
    int ret;

    struct flock the_lock;
    memset(&the_lock, 0, sizeof(the_lock));
    the_lock.l_type = F_ULOCK; 
    the_lock.l_whence = SEEK_SET;
    the_lock.l_start = 0;
    the_lock.l_len = 0; // all the file

    do
    {
        ret = fcntl(fd, F_SETLK, &the_lock);
    } while (ret < 0 && errno == EINTR);

    return ret;
 
}

void activate_oobinline(int fd)
{
    int oob_line = 1;
    int ret;
    ret = setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &oob_line, sizeof(oob_line));
    if (ret == -1)
    {
        err_sys("setsockopt");
    }
}

void activate_sigurg(int fd)
{
    int ret;
    ret = fcntl(fd, F_SETOWN, getpid());
    if (ret == -1)
    {
        err_sys("fcntl");
    }
}
