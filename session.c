#include "session.h"
#include "common.h"
#include "ftpproto.h"
#include "privparent.h"

void begin_session(session_t *sess)
{
    int sockfd[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd) < 0)
        err_sys("socketpair");

    pid_t pid;
    pid = fork();
    if (pid < 0)
        err_sys("fork");

    if (pid == 0)
    {
        // ftp服务进程
        close(sockfd[0]);
        sess->child_fd = sockfd[1];
        handle_child(sess);
    }
    else
    {
        // nobody进程
        close(sockfd[1]);
        sess->parent_fd = sockfd[0];
        handle_parent(sess);
    }
}
