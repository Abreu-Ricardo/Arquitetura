#include "packet.h"

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

    while (1) {
        // Get message from user
        printf("Enter message (or 'quit' to exit): ");
        fgets(msg.data, BUFFER_SIZE, stdin);
        
        if (strcmp(msg.data, "quit\n") == 0) {
            break;
        }

        // Send message to server
        send(sockfd, msg.data, strlen(msg.data), 0);
        
        // Receive response
        recv(sockfd, msg.data, BUFFER_SIZE, 0);
        printf("Server response: %s\n", msg.data);
    }

    close(sockfd);
    return 0;
}
