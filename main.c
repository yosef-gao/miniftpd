#include "common.h"
#include "sysutil.h"
#include "session.h"
#include "parseconf.h"
#include "tunable.h"
#include "ftpproto.h"
#include "ftpcodes.h"

static unsigned int num_child;
void handle_sig_chld(int sig);

int main(int argc, char *argv[])
{
    // list_common(NULL);
    //  测试配置文件读取
    parseconf_load_file(MINIFTP_CONF);
    /*
       printf("tunable_pasv_enable=%d\n", tunable_pasv_enable);
       printf("tunable_port_enable%d\n", tunable_port_enable);
       printf("tunable_listen_port=%u\n", tunable_listen_port);
       printf("tunable_max_clients=%u\n", tunable_max_clients);
       printf("tunable_max_per_ip=%u\n", tunable_max_per_ip);
       printf("tunable_accept_timeout=%u\n", tunable_accept_timeout);
       printf("tunable_connect_timeout=%u\n", tunable_connect_timeout);
       printf("tunable_idle_session_timeout=%u\n", tunable_idle_session_timeout);
       printf("tunable_data_connection_timeout=%u\n", tunable_data_connection_timeout);
       printf("tunable_local_umask=0%o\n", tunable_local_umask);
       printf("tunable_upload_max_rate=%u\n", tunable_upload_max_rate);
       printf("tunable_download_max_rate=%u\n", tunable_download_max_rate);
       if (tunable_listen_address == NULL)
       printf("tunable_listen_address=NULL\n");
       else
       printf("tunable_listen_address=%s\n", tunable_listen_address);
       */

    if (getuid() != 0)
    {
        fprintf(stderr, "miniftpd: must be started as root\n");
        exit(EXIT_FAILURE);
    }
    /*
       typedef struct session
       {
        // 控制连接
        int ctrl_fd;
        uid_t uid;
        char cmdline[MAX_COMMAND_LINE];
        char cmd[MAX_COMMAND];
        char arg[MAX_ARG];

        // 数据连接
        struct sockaddr_in *port_addr; // port 模式下对方的port_addr
        int pasv_listen_fd;
        int data_fd;

        // 父子进程通道
        int parent_fd;
        int child_fd;

        // FTP协议状态
        int is_ascii;
        long long restart_pos;
        char *rnft_name;
        } session_t;

     * */

    session_t sess = 
    {
        /* 控制连接 */
        -1, 0, "", "", "",
        /* 数据连接 */
        NULL, -1, -1, 0,
        /* 父子进程通道 */
        -1, -1,
        /* FTP协议状态 */
        0, 0, NULL,
        /* 连接数限制*/
        0
    };


    signal(SIGCHLD, handle_sig_chld);
    int listenfd = tcp_server(tunable_listen_address, 5188);
    int conn;
    pid_t pid;
    num_child = 0;

    while (1)
    {
        if ((conn = accept(listenfd, NULL, NULL)) < 0)
            err_sys("accept");

        ++num_child;
        sess.num_clients = num_child;
        pid = fork();
        if (pid == -1)
        {
            --num_child;
            err_sys("fork");
        }

        if (pid == 0)
        {
            close(listenfd);
            sess.ctrl_fd = conn;
            // 判断连接数
            if (tunable_max_clients > 0 && sess.num_clients > tunable_max_clients)
            {
                char msg[1024];
                sprintf(msg, "%d %s\r\n", FTP_TRANSFEROK, "There are too many connected users, pleasr try later.");
                writen(sess.ctrl_fd, msg, sizeof(msg));
                exit(EXIT_FAILURE);
            }
            begin_session(&sess);
        }
        else
        {
            close(conn);
        }
    }

    return 0;
}


void handle_sig_chld(int sig)
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
        --num_child;
}
