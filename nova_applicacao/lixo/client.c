// Compile with: gcc -o raw_client raw_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>

#define SERVER_PORT 12345
#define CLIENT_PORT 54321  // Must match what server replies to
#define BUF_SIZE 2048

double time_diff_ms(struct timespec start, struct timespec end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 +
           (end.tv_nsec - start.tv_nsec) / 1.0e6;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <num_packets>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server_ip = argv[1];
    int num_packets = atoi(argv[2]);

    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUF_SIZE];
    socklen_t addr_len = sizeof(server_addr);

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Bind to known port so raw server can reply to it
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = htons(CLIENT_PORT);

    if (bind(sockfd, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Set timeout for receiving response
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Set server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, server_ip, &server_addr.sin_addr);

    for (int i = 0; i < num_packets; i++) {
        struct timespec start, end;

        const char *msg = "Request (raw)";
        clock_gettime(CLOCK_MONOTONIC, &start);

        if (sendto(sockfd, msg, strlen(msg), 0,
                   (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("sendto failed");
            continue;
        }

        int len = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
        clock_gettime(CLOCK_MONOTONIC, &end);

        if (len > 0) {
            buffer[len] = '\0';
            double latency = time_diff_ms(start, end);
            printf("Reply %d: %s | Latency: %.3f ms\n", i + 1, buffer, latency);
        } else {
            perror("Timeout or receive error");
        }
    }

    close(sockfd);
    return 0;
}

