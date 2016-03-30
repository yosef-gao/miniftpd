#ifndef _SYS_UTIL_H_
#define _SYS_UTIL_H_

#include "common.h"

int tcp_server(const char *host, unsigned short port);

int tcp_client(struct sockaddr_in *addr, unsigned short port);

int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds);

int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds);

int getlocalip(char *ip_str);

ssize_t readn(int filedes, void *buff, size_t nbytes);

ssize_t writen(int filedes, const void *buff, size_t nbytes);

ssize_t readline(int filedes, void *buff, size_t maxlen);

int send_fd(int fd, int fd_to_send);

int send_err(int fd, int status, const char *errmsg);

int recv_fd(int fd, ssize_t (*userfunc)(int , const void *, size_t));

void statbuf_get_perms(struct stat *sbuf, char *perms);

void statebuf_get_datetime(struct stat *sbuf, char *datebuf, size_t buf_size);

int lock_file_read(int fd);

int lock_file_write(int fd);

int unlock_file(int fd);

void activate_oobinline(int fd);

void activate_sigurg(int fd);
#endif /* _SYS_UTIL_H_ */
