#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/umem_fd.sock"

int main() {
    int listen_fd, conn_fd;
    struct sockaddr_un addr;
    char buf[1] = {0};

    // Simulated UMEM FD (open a file instead)
    int umem_fd = open("/tmp/fake_umem_file", O_CREAT | O_RDWR, 0666);
    if (umem_fd < 0) {
        perror("open");
        exit(1);
    }

    // Create listening UNIX socket
    if ((listen_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    unlink(SOCKET_PATH); // remove any old socket file
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(listen_fd, 1) < 0) {
        perror("listen");
        exit(1);
    }

    printf("proc A: Waiting for proc B to connect...\n");

    conn_fd = accept(listen_fd, NULL, NULL);
    if (conn_fd < 0) {
        perror("accept");
        exit(1);
    }

    printf("proc A: proc B connected, sending UMEM FD...\n");

    struct msghdr msg = {0};
    struct iovec io = { .iov_base = buf, .iov_len = sizeof(buf) };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(int));

    memcpy(CMSG_DATA(cmsg), &umem_fd, sizeof(int));

    if (sendmsg(conn_fd, &msg, 0) < 0) {
        perror("sendmsg");
        exit(1);
    }

    printf("proc A: UMEM FD sent. Press Enter to exit.\n");
    getchar(); // keep process alive so UMEM stays valid

    close(umem_fd);
    close(conn_fd);
    close(listen_fd);
    unlink(SOCKET_PATH);

    return 0;
}
