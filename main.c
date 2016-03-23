#include "common.h"
#include "sysutil.h"
#include "session.h"

int main(int argc, char *argv[])
{
    if (getuid() != 0)
    {
        fprintf(stderr, "miniftpd: must be started as root\n");
        exit(EXIT_FAILURE);
    }

    session_t sess =
    {
        /* 控制连接 */
        -1, "", "", "",
        /* 父子进程通道 */
        -1, -1
    };

    int listenfd = tcp_server(NULL, 5188);
    int conn;
    pid_t pid;

    while (1)
    {
        if ((conn = accept(listenfd, NULL, NULL)) < 0)
            err_sys("accept");

        pid = fork();
        if (pid == -1)
            err_sys("fork");

        if (pid == 0)
        {
            close(listenfd);
            sess.ctrl_fd = conn;
            begin_session(&sess);
        }
        else
        {
            close(conn);
        }
    }

    return 0;
}
