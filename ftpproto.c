#include "ftpproto.h"
#include "sysutil.h"
#include "strutil.h"
#include "common.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"

void ftp_reply(int fd, int code, const char *msg);
void ftp_lreply(int fd, int code, const char *msg);

int list_common(session_t *sess, int detail);
int get_transfer_fd(session_t *sess);
int port_active(session_t *sess);
int pasv_active(session_t *sess);
int get_port_fd(session_t *sess);
int get_pasv_fd(session_t *sess);
void upload_common(session_t *sess, int is_append);
static void do_site_chmod(const char *arg);
static void do_site_umask(const char *arg);

void handle_ctrl_alarm_timeout(int sig);
void handle_data_alarm_timeout(int sig);
void start_ctrl_alarm(void);
void start_data_alarm(void);
void handle_sigurg(int sig);
    
static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
static void do_stru(session_t *sess);
static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);

typedef struct ftpcmd
{
    const char *cmd;
    void (*cmd_handler)(session_t *sess);
} ftpcmd_t;

static ftpcmd_t ctrl_cmds[] =
{
    /* 访问控制命令 */
    {"USER", do_user},
    {"PASS", do_pass},
    {"CWD", do_cwd},
    {"XCWD", do_cwd},
    {"CDUP", do_cdup},
    {"XCUP", do_cdup},
    {"QUIT", do_quit},
    {"ACCT", NULL},
    {"SMNT", NULL},
    {"REIN", NULL},
    /* 传输参数命令 */
    {"PORT", do_port},
    {"PASV", do_pasv},
    {"TYPE", do_type},
    {"STRU", do_stru},
    {"MODE", do_mode},
    /* 服务命令 */
    {"RETR", do_retr},
    {"STOR", do_stor},
    {"APPE", do_appe},
    {"LIST", do_list},
    {"NLST", do_nlst},
    {"REST", do_rest},
    {"ABOR", do_abor},
    {"\377\364\377\362ABOR", do_abor},
    {"PWD", do_pwd},
    {"XPWD", do_pwd},
    {"MKD", do_mkd},
    {"XMKD", do_mkd},
    {"RMD", do_rmd},
    {"XRMD", do_rmd},
    {"DELE", do_dele},
    {"RNFR", do_rnfr},
    {"RNTO", do_rnto},
    {"SITE", do_site},
    {"SYST", do_syst},
    {"FEAT", do_feat},
    {"SIZE", do_size},
    {"STAT", do_stat},
    {"NOOP", do_noop},
    {"HELP", do_help},
    {"STOU", NULL},
    {"ALLO", NULL}
};

static void do_site_chmod(const char *arg)
{
    if (strlen(arg) == 0)
    {
        ftp_reply(p_sess->ctrl_fd, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
        return;
    }

    char perm[100] = {0};
    char file[100] = {0};
    str_split(arg, perm, file, ' ');
    if (strlen(file) == 0)
    {
        ftp_reply(p_sess->ctrl_fd, FTP_BADCMD, "SITE CHMOD needs w arguments.");
        return;
    }

    unsigned int mode = str_octal_to_uint(perm);
    if (chmod(file, mode) < 0)
    {
        ftp_reply(p_sess->ctrl_fd, FTP_CHMODOK, "SITE CHMOD command fialed.");
        return;
    }

    ftp_reply(p_sess->ctrl_fd, FTP_CHMODOK, "SITE CHMOD command ok.");
}

static void do_site_umask(const char *arg)
{
    char msg[1024] = {0};
    if (strlen(arg) == 0)
    {
        sprintf(msg, "You current umask is 0%o", tunable_local_umask);
        ftp_reply(p_sess->ctrl_fd, FTP_UMASKOK, msg);
    }
    else
    {
        unsigned int um = str_octal_to_uint(arg);
        umask(um);
        sprintf(msg, "UMASK set to 0%o", um);
        ftp_reply(p_sess->ctrl_fd, FTP_UMASKOK, msg);
    }
}

void handle_ctrl_alarm_timeout(int sig)
{
    shutdown(p_sess->ctrl_fd, SHUT_RD); // 关闭读端
    ftp_reply(p_sess->ctrl_fd, FTP_IDLE_TIMEOUT, "Timeout.");
    shutdown(p_sess->ctrl_fd, SHUT_WR);
    exit(EXIT_SUCCESS);
}

void handle_data_alarm_timeout(int sig)
{
    if (!p_sess->data_transmission)
    {
        ftp_reply(p_sess->ctrl_fd, FTP_ADTA_TIMEOUT, "Data timeout. Reconnect. Sorry.");
        exit(EXIT_SUCCESS);
    }

    // 否则，当前处于数据传输的状态收到了信号
    p_sess->data_transmission = 0;
    start_data_alarm();
}

void handle_sigurg(int sig)
{
    if (p_sess->data_transmission == 0)
    {
        return;
    }

    int ret = readline(p_sess->ctrl_fd, p_sess->cmdline, MAX_COMMAND_LINE);
    if (ret <= 0)
    {
        err_sys("readline");
    }

    // 去除\r\n
    str_trim_crlf(p_sess->cmdline);
    printf("cmdline=[%s]\n", p_sess->cmdline);
    // 解析FTP命令与参数
    str_split(p_sess->cmdline, p_sess->cmd, p_sess->arg, ' ');
    printf("cmd=[%s] arg=[%s]\n", p_sess->cmd, p_sess->arg);
    // 将命令转换为大写
    str_upper(p_sess->cmd);
    if (strcmp(p_sess->cmd, "ABOR") == 0 
            || strcmp(p_sess->cmd, "\377\364\377\362ABOR"))
    {
        if (p_sess->data_transmission != 0)
        {
            if (p_sess->data_fd > 0)
                shutdown(p_sess->data_fd, SHUT_RDWR);
            p_sess->data_transmission = 0;
            ftp_reply(p_sess->ctrl_fd, FTP_ABOROK, "ABOR successful.");
        }
        else
        {
            ftp_reply(p_sess->ctrl_fd, FTP_ABOROK, "ABOR successful.");
        }
    }
    else
    {
        ftp_reply(p_sess->data_fd, FTP_BADCMD, "Unknown command.");
    }
}

void start_ctrl_alarm(void)
{
    if (tunable_idle_session_timeout > 0)
    {
        // 安装信号
        if (signal(SIGALRM, handle_ctrl_alarm_timeout) == SIG_ERR)
            err_sys("signal ctrl alarm");
        // 启动闹钟
        alarm(tunable_idle_session_timeout);
    }
}

void start_data_alarm(void)
{
    if (tunable_data_connection_timeout > 0)
    {
        // 安装信号
        if (signal(SIGALRM, handle_data_alarm_timeout) == SIG_ERR)
            err_sys("signal data alarm");
        // 启动闹钟
        alarm(tunable_data_connection_timeout);
    }
    else if (tunable_idle_session_timeout > 0)
    {
        // 关闭先前安装的闹钟
        alarm(0);
    }
}

void handle_child(session_t *sess)
{
    p_sess = sess;
    ftp_reply(sess->ctrl_fd, FTP_GREET, "(miniftpd 0.1)");
    int ret;
    while (1)
    {
        memset(&sess->cmdline, 0, sizeof(sess->cmdline));
        memset(&sess->cmd, 0, sizeof(sess->cmd));
        memset(&sess->arg, 0, sizeof(sess->arg));

        start_ctrl_alarm(); // 在规定时间内收到命令。则会重设闹钟

        ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
        if (ret == -1)
            err_sys("readline");
        else if (ret == 0)
            exit(EXIT_SUCCESS);

        // 去除\r\n
        str_trim_crlf(sess->cmdline);
        printf("cmdline=[%s]\n", sess->cmdline);
        // 解析FTP命令与参数
        str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
        printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
        // 将命令转换为大写
        str_upper(sess->cmd);
        // 处理FTP命令
        int i = 0;
        int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
        for (i = 0; i < size; ++i)
        {
            if (strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0)
            {
                if (ctrl_cmds[i].cmd_handler != NULL)
                {
                    ctrl_cmds[i].cmd_handler(sess);
                }
                else
                {
                    ftp_reply(sess->ctrl_fd, FTP_COMMANDNOTIMPL, "Unimlement command.");
                }
                break;
            }
        }
        if (i == size)
        {
            ftp_reply(sess->ctrl_fd, FTP_BADCMD, "Unknown command.");
        }
    }
}

void ftp_reply(int fd, int code, const char *msg)
{
    char buff[1024] = {0};
    sprintf(buff, "%d %s\r\n", code, msg);
    writen(fd, buff, strlen(buff));
}

void ftp_lreply(int fd, int code, const char *msg)
{
    char buff[1024] = {0};
    sprintf(buff, "%d-%s\r\n", code, msg);
    writen(fd, buff, strlen(buff));
}

int list_common(session_t *sess, int detail)
{
    DIR *dir = opendir(".");
    if (dir == NULL)
    {
        return 0;
    }

    struct dirent *dt;
    struct stat sbuf;
    while ((dt = readdir(dir)) != NULL)
    {
        if (lstat(dt->d_name, &sbuf) < 0)
            continue;

        if (dt->d_name[0] == '.')
            continue;

        char buf[1024] = {0};
        if (detail)
        {
            // get stat perms
            char perms[] = "?---------";
            statbuf_get_perms(&sbuf, perms);

            int off = 0;
            off += sprintf(buf, "%s ", perms);
            off += sprintf(buf + off, "%3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
            off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);

            // get datetime
            char datebuf[64] = {0};
            statebuf_get_datetime(&sbuf, datebuf, sizeof(datebuf));
            off += sprintf(buf + off, "%s ", datebuf);

            // filename
            if (perms[0] == 'l')
            {
                char tmp[1024] = {0};
                readlink(dt->d_name, tmp, sizeof(tmp));
                off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
            }
            else
            {
                off += sprintf(buf + off, "%s\r\n", dt->d_name);
            }
        }
        else
        {
            sprintf(buf, "%s\r\n", dt->d_name);
        }

        writen(sess->data_fd, buf, strlen(buf));
    }

    closedir(dir);

    return 1;
}

int port_active(session_t *sess)
{
    if (sess->port_addr != NULL)
    {
        if (pasv_active(sess))
        {
            fprintf(stderr, "pasv is actived\n");
            exit(EXIT_FAILURE);
        }
        return 1;
    }

    return 0;
}

int pasv_active(session_t *sess)
{
    priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
    int active = priv_sock_get_int(sess->child_fd);
    if (active)
    {
        if (port_active(sess))
        {
            fprintf(stderr, "pasv is actived\n");
            exit(EXIT_FAILURE);
        }
        return 1;
    }
    return 0;
}

int get_port_fd(session_t *sess)
{
    int ret = 1;

    priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
    unsigned short port = ntohs(sess->port_addr->sin_port);
    char *ip = inet_ntoa(sess->port_addr->sin_addr);
    priv_sock_send_int(sess->child_fd, (int)port);
    priv_sock_send_buf(sess->child_fd, ip, strlen(ip));

    char res = priv_sock_get_result(sess->child_fd);
    if (res == PRIV_SOCK_RESULT_BAD)
    {
        ret = 0;
    }
    else if (res == PRIV_SOCK_RESULT_OK)
    {
        sess->data_fd = priv_sock_recv_fd(sess->child_fd);
    }

    return ret;
}

int get_pasv_fd(session_t *sess)
{
    priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCETP);

    char res = priv_sock_get_result(sess->child_fd);
    if (res == PRIV_SOCK_RESULT_BAD)
    {
        return 0;
    }
    else if (res == PRIV_SOCK_RESULT_OK)
    {
        sess->data_fd = priv_sock_recv_fd(sess->child_fd);
    }
    return 1;
}

int get_transfer_fd(session_t *sess)
{
    // 检测是否收到PORT或PASV命令
    if (!port_active(sess) && !pasv_active(sess))
    {
        ftp_reply(sess->ctrl_fd, FTP_BADSENDCONN, "Use PORT or PASV first.");
        return 0;
    }

    // 如果是PASV
    if (port_active(sess))
    {
        if (get_port_fd(sess) == 0)
        {
            return 0;
        }
    }

    if (pasv_active(sess))
    {
        if (get_pasv_fd(sess) == 0)
        {
            return 0;
        }
    }

    if (sess->port_addr != NULL)
    {
        free(sess->port_addr);
        sess->port_addr = NULL;
    }
    return 1;
}

void limit_rate(struct timespec *start_time, int bytes_transfered, long max_rate)
{
    p_sess->data_transmission = 1;
    if (max_rate == 0)
        return;

    // 获取一下当前时间
    struct timespec tsp, time_to_sleep;
    int ret = clock_gettime(CLOCK_REALTIME, &tsp);
    if (ret < 0)
        err_sys("clock_gettime");

    double elapse_time = (tsp.tv_nsec - start_time->tv_nsec) / 1000000000.0 + (tsp.tv_sec - start_time->tv_sec); // sec
    double rate = bytes_transfered / (elapse_time + 0.000000001); // rate = bytes/sec, 防止=0
    if (max_rate >= rate)
    {
        ret = clock_gettime(CLOCK_REALTIME, start_time);
        if (ret < 0)
            err_sys("clock_gettime");
        return;
    }

    double sec_to_sleep = (rate/(double)max_rate - 1) * elapse_time;

    time_to_sleep.tv_sec = (time_t)sec_to_sleep;
    time_to_sleep.tv_nsec = (long)((sec_to_sleep - (double)time_to_sleep.tv_sec) * 1000000000);
    do
    {
        ret = nanosleep(&time_to_sleep, &time_to_sleep);
    } while (ret == -1 && errno == EINTR);

    ret = clock_gettime(CLOCK_REALTIME, start_time);
    if (ret < 0)
        err_sys("clock_gettime");
}

void upload_common(session_t *sess, int is_append)
{
    // 创建数据连接通道
    if (get_transfer_fd(sess) == 0)
    {
        return;
    }

    long long offset = sess->restart_pos;
    sess->restart_pos = 0;

    // 打开文件 0666 & ~umask
    int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666);
    if (fd == -1)
    {
        ftp_reply(sess->ctrl_fd, FTP_UPLOADFAIL, "Counld not create file.");
        return;
    }

    int ret = 0;
    // 加写锁
    ret = lock_file_write(fd);
    if (ret == -1)
    {
        ftp_reply(sess->ctrl_fd, FTP_UPLOADFAIL, "Counld not create file.");
        return;
    }

    // 判断哪种模式
    if (!is_append) // STOR
    {
        if (offset != 0)
        {
            ftruncate(fd, 0);
            ret = lseek(fd, 0, SEEK_SET);
        }
        else if (offset != 0) // REST + STOR
        {
            ret = lseek(fd, offset, SEEK_SET);
        }
    }
    else // APPE
    {
        ret = lseek(fd, 0, SEEK_END);
    }

    if (ret < 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_UPLOADFAIL, "Counld not create file.");
    }

    // 150
    struct stat sbuf;
    ret = fstat(fd, &sbuf);
    char msg[4096] = {0};
    if (sess->is_ascii)
    {
        sprintf(msg, "Opening ASCII mode data connection for %s (%lld bytes)", sess->arg, (long long)sbuf.st_size);
    }
    else
    {
        sprintf(msg, "Opening BINARY mode data connection for %s (%lld bytes)", sess->arg, (long long)sbuf.st_size);
    }
    ftp_reply(sess->ctrl_fd, FTP_DATACONN, msg);

    // 限速功能 睡眠时间 = （当前传输速度/最大传输速度-1）*当前传输时间；
    // 上传文件
    char buf[4096];
    int flag = 0;
    struct timespec start_time;
    ret = clock_gettime(CLOCK_REALTIME, &start_time);
    if (ret < 0)
        err_sys("clock_gettime");

    // 重新安装信号SIGNAL，并启动闹钟
    start_data_alarm();
    while (1)
    {
        ret = read(sess->data_fd, buf, sizeof(buf));
        if (ret == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                flag = 2;
                break;
            }
        }
        else if (ret == 0) // EOF
        {
            flag = 0;
            break;
        }
        else
        {
            limit_rate(&start_time, ret, tunable_upload_max_rate);
            if (ret != writen(fd, buf, ret)) // 写入套接字失败
            {
                flag = 1;
                break;
            }
        }
    }

    // 关闭文件 关闭数据套接字
    close(fd);
    close(sess->data_fd);
    sess->data_fd = -1;
    sess->data_transmission = 0;

    // 226
    if (flag == 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_TRANSFEROK, "Transfer complete.");
    }
    else if (flag == 1)
    {
        ftp_reply(sess->ctrl_fd, FTP_BADSENDFILE, "Faild to write file.");
    }
    else if (flag == 2)
    {
        ftp_reply(sess->ctrl_fd, FTP_BADSENDNET, "Faild to read stream.");
    }

    start_ctrl_alarm();
}

static void do_user(session_t *sess)
{
    struct passwd *pw = getpwnam(sess->arg);
    if (pw == NULL)
    {
        // 用户不存在
        ftp_reply(sess->ctrl_fd, FTP_LOGINERR, "User not exist.");
        // writen(sess->ctrl_fd, FTP_530, strlen(FTP_530));
        return;
    }

    sess->uid = pw->pw_uid;
    ftp_reply(sess->ctrl_fd, FTP_GIVEPWORD, "Please specify the password.");
    // writen(sess->ctrl_fd, FTP_331, strlen(FTP_331));
}

static void do_pass(session_t *sess)
{
    struct passwd *pw = getpwuid(sess->uid);
    if (pw == NULL)
    {
        // 用户不存在
        ftp_reply(sess->ctrl_fd, FTP_LOGINERR, "User not exist.");
        // writen(sess->ctrl_fd, FTP_530, strlen(FTP_530));
        return;
    }

    struct spwd *sp = getspnam(pw->pw_name);
    if (sp == NULL)
    {
        ftp_reply(sess->ctrl_fd, FTP_LOGINERR, "User error.");
        // writen(sess->ctrl_fd, FTP_530, strlen(FTP_530));
        return;
    }

    // 对密码明文进行加密
    char* encrypted_pass = crypt(sess->arg, sp->sp_pwdp);
    if (strcmp(encrypted_pass, sp->sp_pwdp) != 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_LOGINERR, "Error password.");
        // writen(sess->ctrl_fd, FTP_530, strlen(FTP_530));
        return;
    }


    umask(tunable_local_umask);
    if (setegid(pw->pw_gid) < 0)
        err_sys("setegid");
    if (seteuid(pw->pw_uid) < 0)
        err_sys("seteuid");
    if (chdir(pw->pw_dir) < 0)
        err_sys("chdir");

    ftp_reply(sess->ctrl_fd, FTP_LOGINOK, "Login successful.");
    activate_sigurg(sess->ctrl_fd);
    signal(SIGURG, handle_sigurg);
}

static void do_cwd(session_t *sess)
{
    if (chdir(sess->arg) < 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "Failed to change diectory.");
    }
    else
    {
        ftp_reply(sess->ctrl_fd, FTP_CWDOK, "Directory successfully changed.");
    }
}

static void do_cdup(session_t *sess)
{
    if (chdir("..") < 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "Failed to change diectory.");
    }
    else
    {
        ftp_reply(sess->ctrl_fd, FTP_CWDOK, "Directory successfully changed.");
    }
}

static void do_quit(session_t *sess)
{
    ftp_reply(sess->ctrl_fd, FTP_GOODBYE, "Goodbye.");
    exit(EXIT_SUCCESS);
}

static void do_port(session_t *sess)
{
    // PORT 10,8,204,173,14,161
    unsigned int v[6];
    sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
    sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    bzero(sess->port_addr, sizeof(*sess->port_addr));
    sess->port_addr->sin_family = AF_INET;

    unsigned short int port = (v[0] << 8) | v[1];
    sess->port_addr->sin_port = htons(port);
    char ip_addr_str[] = "255.255.255.255";
    sprintf(ip_addr_str, "%u.%u.%u.%u", v[2], v[3], v[4], v[5]);
    if (inet_aton(ip_addr_str, &sess->port_addr->sin_addr) < 0)
        err_sys("inet_aton");

    ftp_reply(sess->ctrl_fd, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

static void do_pasv(session_t *sess)
{
    priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
    unsigned short port = (unsigned short)priv_sock_get_int(sess->child_fd);
    unsigned int v[4];
    sscanf(tunable_listen_address, "%u.%u.%u.%u", &v[0], &v[1], &v[2], &v[3]);
    char msg[1024];
    sprintf(msg, "Entering Passive Mode (%u,%u,%u,%u,%u,%u)", v[0], v[1], v[2], v[3], (port >> 8)&0xFF, port & 0xFF);
    ftp_reply(sess->ctrl_fd, FTP_PASVOK, msg);
}

static void do_type(session_t *sess)
{
    if (strcmp(sess->arg, "A") == 0)
    {
        sess->is_ascii = 1;
        ftp_reply(sess->ctrl_fd, FTP_TYPEOK, "Switching to ASCII mode.");
    }
    else if (strcmp(sess->arg, "I") == 0)
    {
        sess->is_ascii = 0;
        ftp_reply(sess->ctrl_fd, FTP_TYPEOK, "Switching to Binary mode.");
    }
    else
    {
        ftp_reply(sess->ctrl_fd, FTP_BADCMD, "Unrecognized TYPE command.");
    }
}

static void do_stru(session_t *sess)
{}
static void do_mode(session_t *sess)
{}

static void do_retr(session_t *sess)
{
    // 下载文件
    // 断点续传
    long long offset = sess->restart_pos;
    sess->restart_pos = 0;

    // 创建数据连接
    if (get_transfer_fd(sess) == 0)
    {
        return;
    }
    // 打开文件
    int fd = open(sess->arg, O_RDONLY);
    if (fd == -1)
    {
        ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "Failed to open file.");
        return;
    }

    // 文件加读锁
    int ret = lock_file_read(fd);
    // 判断是否是普通文件
    struct stat sbuf;
    ret = fstat(fd, &sbuf);
    if (!S_ISREG(sbuf.st_mode))
    {
        ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "Not a regualar file.");
        return;
    }

    if (offset != 0)
    {
        ret = lseek(fd, offset, SEEK_SET);
        if (ret == -1)
        {
            ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "Failed to seek file.");
            return;
        }
    }

    // 150
    char msg[1024] = {0};
    if (sess->is_ascii)
    {
        sprintf(msg, "Opening ASCII mode data connection for %s (%lld bytes)", sess->arg, (long long)sbuf.st_size);
    }
    else
    {
        sprintf(msg, "Opening BINARY mode data connection for %s (%lld bytes)", sess->arg, (long long)sbuf.st_size);
    }
    ftp_reply(sess->ctrl_fd, FTP_DATACONN, msg);

    // 下载文件
    // 该方法效率不高
    /*
       char buf[4096];
       int flag = 0;
       while (1)
       {
       ret = read(fd, buf, 4096);
       if (ret == -1)
       {
       if (errno == EINTR)
       {
       continue;
       }
       else
       {
       flag = 1;
       break;
       }
       }
       else if (ret == 0) // EOF
       {
       flag = 0;
       break;
       }
       else
       {
       if (ret != writen(sess->data_fd, buf, ret)) // 写入套接字失败
       {
       flag = 2;
       break;
       }
       }
       }
       */

    // 计算文件大小
    int flag = 0;
    long long bytes_to_send = sbuf.st_size;
    if (offset > bytes_to_send)
        bytes_to_send = 0;
    else
        bytes_to_send -= offset;

    start_data_alarm();
    struct timespec start_time;
    ret = clock_gettime(CLOCK_REALTIME, &start_time);
    while (bytes_to_send)
    {
        int num_this_time = (bytes_to_send > 4096 ? 4096 : bytes_to_send);
        ret = sendfile(sess->data_fd, fd, NULL, num_this_time);
        if (ret == -1)
        {
            flag = 2;
            break;
        }
        bytes_to_send -= ret;
        limit_rate(&start_time, ret, tunable_download_max_rate);
    }

    // 关闭数据套接字 打开的文件
    close(sess->data_fd);
    sess->data_fd = -1;
    close(fd);
    sess->data_transmission = 0;
    // 226
    if (flag == 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_TRANSFEROK, "Transfer complete.");
    }
    else if (flag == 1)
    {
        ftp_reply(sess->ctrl_fd, FTP_BADSENDFILE, "Faild reading file.");
    }
    else if (flag == 2)
    {
        ftp_reply(sess->ctrl_fd, FTP_BADSENDNET, "Faild writing to stream.");
    }

    // 重新启动控制连接闹钟
    start_ctrl_alarm();
}

static void do_stor(session_t *sess)
{
    upload_common(sess, 0);
}

static void do_appe(session_t *sess)
{
    upload_common(sess, 1);
}

static void do_list(session_t *sess)
{
    // 创建数据连接
    if (get_transfer_fd(sess) == 0)
    {
        return;
    }
    // PORT
    // PASV
    // 150
    ftp_reply(sess->ctrl_fd, FTP_DATACONN, "Here comes the directory listing.");
    // 传输列表
    list_common(sess, 1);
    // 关闭数据连接套接字
    close(sess->data_fd);
    sess->data_fd = -1;
    // 226
    ftp_reply(sess->ctrl_fd, FTP_TRANSFEROK, "Directory send ok.");
}

static void do_nlst(session_t *sess)
{
    // 创建数据连接
    if (get_transfer_fd(sess) == 0)
    {
        return;
    }
    // PORT
    // PASV
    // 150
    ftp_reply(sess->ctrl_fd, FTP_DATACONN, "Here comes the directory listing.");
    // 传输列表
    list_common(sess, 0);
    // 关闭数据连接套接字
    close(sess->data_fd);
    sess->data_fd = -1;
    // 226
    ftp_reply(sess->ctrl_fd, FTP_TRANSFEROK, "Directory send ok.");
}

static void do_rest(session_t *sess)
{
    sess->restart_pos = str_to_longlong(sess->arg);
    char msg[1024] = {0};
    sprintf(msg, "Restart position accepted (%s).", sess->arg);
    ftp_reply(sess->ctrl_fd, FTP_RESTOK, msg);
}

static void do_abor(session_t *sess)
{
    ftp_reply(sess->ctrl_fd, FTP_ABOR_NOCONN, "No transfer to ABOR.");
}

static void do_pwd(session_t *sess)
{
    char msg[PATH_MAX + 3];
    char dir[PATH_MAX + 1];
    getcwd(dir, PATH_MAX);
    sprintf(msg, "\"%s\"", dir);
    ftp_reply(sess->ctrl_fd, FTP_PWDOK, msg);
}

static void do_mkd(session_t *sess)
{
    // umask & 0777
    if (mkdir(sess->arg, 0777) < 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "Create directory operation failed.");
        return;
    }

    char msg[4096] = {0};
    if (sess->arg[0] == '/')
    {
        sprintf(msg, "\"%s\" created", sess->arg);
    }
    else
    {
        char dir[4096 + 1];
        getcwd(dir, 4096);
        if (dir[strlen(dir) - 1] == '/')
        {
            sprintf(msg, "\"%s%s\" created", dir, sess->arg);
        }
        else
        {
            sprintf(msg, "\"%s/%s\" created", dir, sess->arg);
        }
    }
    ftp_reply(sess->ctrl_fd, FTP_MKDIROK, msg);
}

static void do_rmd(session_t *sess)
{
    if (rmdir(sess->arg) < 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "Remove directory operation failed.");
        return;
    }

    ftp_reply(sess->ctrl_fd, FTP_RMDIROK, "Remove directory operation successful.");
}

static void do_dele(session_t *sess)
{
    if (unlink(sess->arg) < 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "Delete operation failed.");
        return;
    }

    ftp_reply(sess->ctrl_fd, FTP_DELEOK, "Delete operation successful.");
}

static void do_rnfr(session_t *sess)
{
    sess->rnft_name = malloc(strlen(sess->arg) + 1);
    memset(sess->rnft_name, 0, strlen(sess->arg) + 1);
    strcpy(sess->rnft_name, sess->arg);
    ftp_reply(sess->ctrl_fd, FTP_RNFROK, "Ready for RNTO.");
}

static void do_rnto(session_t *sess)
{
    if (sess->rnft_name == NULL)
    {
        ftp_reply(sess->ctrl_fd, FTP_NEEDRNFR, "RNFR required first.");
        return;
    }

    rename(sess->rnft_name, sess->arg);
    ftp_reply(sess->ctrl_fd, FTP_RENAMEOK, "Rename successful.");

    free(sess->rnft_name);
    sess->rnft_name = NULL;
}

static void do_site(session_t *sess)
{
    char cmd[100] = {0};
    char arg[100] = {0};
    str_split(sess->arg, cmd, arg, ' ');
    if (strcmp(cmd, "CHMOD") == 0)
    {
        do_site_chmod(arg);
    }
    else if (strcmp(cmd, "UMASK") == 0)
    {
        do_site_umask(arg);
    }
    else if (strcmp(cmd, "HELP") == 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_SITEHELP, "CHMOD UMASK HELP");
    }
    else
    {
        ftp_reply(sess->ctrl_fd, FTP_BADCMD, "Unknown site command.");
    }
}

static void do_syst(session_t *sess)
{
    ftp_reply(sess->ctrl_fd, FTP_SYSTOK, "UNIX Type: L8");
}

static void do_feat(session_t *sess)
{
    ftp_lreply(sess->ctrl_fd, FTP_FEAT, "Features:");
    writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
    writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"));
    writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
    writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
    writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
    writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
    writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
    writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
    ftp_reply(sess->ctrl_fd, FTP_FEAT, "End");
}

static void do_size(session_t *sess)
{
    struct stat buf;
    if (stat(sess->arg, &buf) < 0)
    {
        ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "SIZE operation failed.");
        return;
    }

    if (!S_ISREG(buf.st_mode))
    {
        ftp_reply(sess->ctrl_fd, FTP_FILEFAIL, "Could not get file size.");
        return;
    }

    char msg[1024];
    sprintf(msg, "%lld", (long long int)buf.st_size);
    ftp_reply(sess->ctrl_fd, FTP_SIZEOK, msg);
}

static void do_stat(session_t *sess)
{
    ftp_lreply(sess->ctrl_fd, FTP_STATOK, "FTP server status:");
    char msg[1024];
    sprintf(msg, "%s\r\n", "Connected to 192.168.20.177");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", "Logged in as root");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", "TYPE: ASCII");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", "No session bandwidth limit");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", "Session timeout in seconds is 300");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", "Control connection is plain text");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", "Data connections will be plain text");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", "ession startup, client count was 1");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", "FTPd 2.0.6 - secure, fast, stable");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    ftp_reply(sess->ctrl_fd, FTP_STATOK, "End of status.");
}

static void do_noop(session_t *sess)
{
    start_ctrl_alarm();
    ftp_reply(sess->ctrl_fd, FTP_NOOPOK, "NOOP ok");
}

static void do_help(session_t *sess)
{
    ftp_lreply(sess->ctrl_fd, FTP_HELP, "the following connmnds are recognized.");
    char msg[1024];
    sprintf(msg, "%s\r\n", " ABOR ACCT ALLU APPE CDUP CWD DELE EPRT EPSV FEAT HELP LIST MDTM MKD");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", " MODE NLST NOOP OPTS PASS PASV PORT PWD QUIT REIN REST RETR RMD RNFR");
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", " RNTA SITE SIZE SMNT STAT STAR STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD"); 
    writen(sess->ctrl_fd, msg, sizeof(msg));
    sprintf(msg, "%s\r\n", " XPWD XRMD"); 
    writen(sess->ctrl_fd, msg, sizeof(msg));
    ftp_reply(sess->ctrl_fd, FTP_HELP, "Help OK.");
}

