#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 9000
//#define DEST_IP "127.0.0.1"
#define DEST_IP "20.20.20.2"
#define PACKET_SIZE 64

int main() {
    int sockfd;
    struct sockaddr_in dest_addr;
    char buffer[PACKET_SIZE];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(1);
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, DEST_IP, &dest_addr.sin_addr);

    for (int i = 0; i < 100; i++) {
        unsigned long long ts = __rdtsc();
        memcpy(buffer, &ts, sizeof(ts)); // put timestamp in the beginning
        sendto(sockfd, buffer, PACKET_SIZE, 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        //usleep(10000); // 10ms delay between packets
    }

    close(sockfd);
    return 0;
}

