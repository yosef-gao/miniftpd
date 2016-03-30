#ifndef _SESSION_H_
#define _SESSION_H_

#include "common.h"

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
    int data_transmission;

    // 父子进程通道
    int parent_fd;
    int child_fd;
    
    // FTP协议状态
    int is_ascii;
    long long restart_pos;
    char *rnft_name;

    // 连接数限制
    unsigned int num_clients;
} session_t;

void begin_session(session_t *sess);
#endif /* _SESSION_H_ */
