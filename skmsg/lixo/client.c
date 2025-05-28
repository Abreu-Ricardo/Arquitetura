#include "packet.h"

#include "ebpf.skel.h"

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    struct message msg;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(1);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    //inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr));
    inet_pton(AF_INET, "10.10.10.1", &(server_addr.sin_addr));

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connection failed");
        exit(1);
    }

    printf("Connected to server\n");

    char message[] = "Oi do cliente";
    struct iovec iov = {
        .iov_base = message,
        .iov_len = strlen(message)
    };

    struct msghdr mesg = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    struct msghdr resp = {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    while (1) {
        // Get message from user
        printf("Enter message (or 'quit' to exit): ");
        fgets(msg.data, BUFFER_SIZE, stdin);
        
        if (strcmp(msg.data, "quit\n") == 0) {
            break;
        }

        // Send message to server
        //send(sockfd, msg.data, strlen(msg.data), 0);
        if (sendmsg(sockfd, &mesg, 0) < 0){
            perror("Erro no sendmsg()");
        }
        
        // Receive response
        recv(sockfd, msg.data, BUFFER_SIZE, 0);
        //if(recvmsg(sockfd, &resp, 0) < 0){
        //    perror("Erro no recvmsg()");
        //}
        

        printf("Server response: %s\n", msg.data);
        //printf("Server response: %s\n", (char *)resp.msg_iov->iov_base);
    }

    close(sockfd);
    return 0;
}
