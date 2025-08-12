#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/umem_fd.sock"

int main() {
    int sock;
    struct sockaddr_un addr;
    char buf[1];

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    printf("proc B: Connecting to proc A...\n");
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }

    struct msghdr msg = {0};
    struct iovec io = { .iov_base = buf, .iov_len = sizeof(buf) };
    char cmsgbuf[CMSG_SPACE(sizeof(int))];
    memset(cmsgbuf, 0, sizeof(cmsgbuf));

    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);

    if (recvmsg(sock, &msg, 0) < 0) {
        perror("recvmsg");
        exit(1);
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    int received_fd;
    memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(int));

    printf("proc B: Got UMEM FD = %d\n", received_fd);

    // Example: write something into the UMEM file
    write(received_fd, "Hello UMEM!", 12);

    close(received_fd);
    close(sock);
    return 0;
}
