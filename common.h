#ifndef _COMMON_H_
#define _COMMON_H_

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <errno.h>
#include <shadow.h>
#include <crypt.h>
#include <limits.h>
#include <dirent.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <wait.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>



#define MAXLINE 4096
#define LISTENQ 5
#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 32
#define MAX_ARG 1024
#define PORT_ANY 0

#define MINIFTP_CONF "miniftpd.config"

#define FTP_530 "530 Login incorrect.\r\n"
#define FTP_331 "331 Please specify the password.\r\n"
#define FTP_230 "230 Login successful.\r\n"
#define FTP_220 "220 (miniftpd 0.1)\r\n"

void err_ret(const char *fmt, ...);
void err_sys(const char *fmt, ...);
void err_dump(const char *fmt, ...);
void err_msg(const char *fmt, ...);
void err_quit(const char *fmt, ...);
#endif /* _COMMON_H_ */
