#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define PACKET_COUNT 1000

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    socklen_t addr_len = sizeof(client_addr);

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the socket
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Receive 100 packets
    for (int i = 0; i < PACKET_COUNT; i++) {
        ssize_t received_bytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                          (struct sockaddr*)&client_addr, &addr_len);
        if (received_bytes < 0) {
            perror("recvfrom() failed");
            continue;
        }
        buffer[received_bytes] = '\0';  // Null-terminate the received message
        printf("Recebendo pkt...: %s\n", buffer);

        // Send acknowledgment
        char ack_msg[50];
        sprintf(ack_msg, "ACK for packet %d", i + 1);
        sendto(sockfd, ack_msg, strlen(ack_msg), 0, (struct sockaddr*)&client_addr, addr_len);
    }

    printf("Finished receiving and sending 100 packets.\n");
    close(sockfd);
    return 0;
}
