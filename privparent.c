#include "privparent.h"
#include "sysutil.h"
#include "privsock.h"
#include "tunable.h"

static void privop_port_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);
void minimize_privilege(void);

// 没有接口，通过系统调用实现capset
int capset(cap_user_header_t hdrp, cap_user_data_t datap)
{
    return syscall(__NR_capset, hdrp, datap);
}

void minimize_privilege(void)
{
    struct passwd *pw = getpwnam("nobody");
    if (pw == NULL)
        err_sys("getpwnam");

    /* 注意要先改gid,如果先改uid可能就没有权限再修改gid了 */
    if (setegid(pw->pw_gid) < 0)
        err_sys("setegid");
    if (seteuid(pw->pw_uid) < 0)
        err_sys("seteuid");

    /*typedef struct __user_cap_header_struct {
      __u32 version;
      int pid;
      } *cap_user_header_t;

      typedef struct __user_cap_data_struct {
      __u32 effective; // 当前应该具有的capbilities
      __u32 permitted; // 
      __u32 inheritable;
      } *cap_user_data_t;

     * */

    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data;

    memset(&cap_header, 0, sizeof(cap_header));
    memset(&cap_data, 0, sizeof(cap_data));

    cap_header.version = _LINUX_CAPABILITY_VERSION_1; // 32-bit
    cap_header.pid = 0;

    __u32 cap_mask = 0; // set
    cap_mask |= (1 << CAP_NET_BIND_SERVICE);
    cap_data.effective = cap_data.permitted = cap_mask;
    cap_data.inheritable = 0;

    // capset 是一个原始的内核接口，并没有在头文件中声明
    capset(&cap_header, &cap_data);
}

void handle_parent(session_t *sess)
{
    void minimize_privilege(void);
    char cmd;

    while (1)
    {
        // read(sess->parent_fd, &cmd, 1);
        cmd = priv_sock_get_cmd(sess->parent_fd);
        // 解析内部命令
        switch (cmd)
        {
            case PRIV_SOCK_GET_DATA_SOCK:
                privop_port_get_data_sock(sess);
                break;
            case PRIV_SOCK_PASV_ACTIVE:
                privop_pasv_active(sess);
                break;
            case PRIV_SOCK_PASV_LISTEN:
                privop_pasv_listen(sess);
                break;
            case PRIV_SOCK_PASV_ACCETP:
                privop_pasv_accept(sess);
                break;
        }
    }
}

static void privop_port_get_data_sock(session_t *sess)
{
    unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
    char ip[16] = {0};
    priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));

    printf("%s:%d\n", ip, port);

    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int fd = tcp_client(&addr, 20);
    if (fd == -1)
    {
        priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
        return;
    }

    priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
    priv_sock_send_fd(sess->parent_fd, fd);
    close(fd);

    printf("send fd success\n");
}

static void privop_pasv_active(session_t *sess)
{
    int active;
    if (sess->pasv_listen_fd != -1)
        active = 1;
    else
        active = 0;

    priv_sock_send_int(sess->parent_fd, active);
}

static void privop_pasv_listen(session_t *sess)
{
    sess->pasv_listen_fd = tcp_server(tunable_listen_address, PORT_ANY);
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    if (getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &(addrlen)) < 0)
        err_sys("getsockname");
    unsigned short port = ntohs(addr.sin_port);
    priv_sock_send_int(sess->parent_fd, (int)port);
}

static void privop_pasv_accept(session_t *sess)
{
    int fd = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
    close(sess->pasv_listen_fd);

    if (fd == -1)
    {
        priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
        return;
    }
    priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
    priv_sock_send_fd(sess->parent_fd, fd);
    close(fd);
}

