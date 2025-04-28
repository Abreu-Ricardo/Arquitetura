#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>  // For __rdtsc
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_PORT 12345
//#define SERVER_IP "127.0.0.1"
#define SERVER_IP "20.20.20.2"
#define PACKET_SIZE 64
#define CPU_FREQ_HZ 3600000000ULL // Adjust to your CPU freq (e.g., 3.6GHz)

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char send_buf[PACKET_SIZE];
    char recv_buf[PACKET_SIZE];
    socklen_t addr_len = sizeof(server_addr);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    for (int i = 0; i < 1000; i++) {
        uint64_t start = __rdtsc();

        // Send packet
        if (sendto(sockfd, send_buf, sizeof(send_buf), 0,
                   (struct sockaddr *)&server_addr, addr_len) < 0) {
            perror("sendto");
            return 1;
        }

        // Wait for reply
        if (recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                     (struct sockaddr *)&server_addr, &addr_len) < 0) {
            perror("recvfrom");
            return 1;
        }

        uint64_t end = __rdtsc();

        uint64_t cycles = end - start;
        double latency_us = (double)cycles / (CPU_FREQ_HZ / 1e6);

        printf("Packet %d latency: %.2f us (%lu cycles)\n", i+1, latency_us, cycles);

        //usleep(10000); // Sleep 10ms 
    }

    close(sockfd);
    return 0;
}
