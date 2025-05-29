#include "packet.h"

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket creation failed");
        exit(1);
    }

    // Set address reuse option
    int optval = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr));

    // Bind socket to address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    printf("Server listening on port %d...\n", SERVER_PORT);

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(1);
        return 1;
    }

    // Accept connection
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("accept failed");
        exit(1);
    }

    printf("Connection accepted from client\n");

    struct message msg;
    while (1) {
        // Receive message from client
        memset(&msg, 0, sizeof(msg));
        ssize_t bytes_received = recv(client_fd, msg.data, BUFFER_SIZE, 0);
        
        if (bytes_received <= 0) {
            break;
        }
        
        printf("Received: %s\n", msg.data);
        
        // Send response back
        strcpy(msg.data, "Message received by server");
        send(client_fd, msg.data, strlen(msg.data), 0);
    }

    close(client_fd);
    close(server_fd);
    return 0;
}
