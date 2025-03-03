#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

//#define SERVER_IP "127.0.0.1"
#define SERVER_IP "20.20.20.1"
//#define SERVER_IP "20.20.20.1"
#define SERVER_PORT 8080
#define BUFFER_SIZE 1024
#define PACKET_COUNT 1000

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // Send 100 packets and receive acknowledgments
    for (int i = 0; i < PACKET_COUNT; i++) {
        char msg[50];
        sprintf(msg, "Packet %d", i + 1);

        // Send packet
        sendto(sockfd, msg, strlen(msg), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        printf("Enviando pkt...\n");

        // Receive acknowledgment
        socklen_t addr_len = sizeof(server_addr);
        ssize_t received_bytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                          (struct sockaddr*)&server_addr, &addr_len);
        if (received_bytes > 0) {
            buffer[received_bytes] = '\0';
            printf("Received from server: %s\n", buffer);
        }
    }

    printf("Finished sending and receiving 100 packets.\n");
    close(sockfd);
    return 0;
}

