// sk_msg_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {
    int sock;
    struct sockaddr_in server_addr;
    const char *message = "Hello from client via eBPF!";

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345); 
    //server_addr.sin_addr.s_addr = inet_addr("10.10.10.1");
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        exit(1);
    }

    printf("Connected to server. Sending message...\n");

    ssize_t sent = send(sock, message, strlen(message), 0);
    if (sent < 0) {
        perror("send");
        close(sock);
        exit(1);
    }

    printf("Sent %zd bytes\n", sent);

    close(sock);
    return 0;
}
