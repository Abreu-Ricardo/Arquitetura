#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 9000
#define PACKET_SIZE 64

// Helper to get TSC frequency from /proc/cpuinfo
double get_tsc_freq_mhz() {
    
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        perror("fopen /proc/cpuinfo");
        exit(1);
    }

    char line[256];
    double mhz = 0.0;

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "cpu MHz\t: %lf", &mhz) == 1) {
            fclose(fp);
            return mhz;
        }
    }

    fclose(fp);
    fprintf(stderr, "Could not find CPU MHz in /proc/cpuinfo\n");
    exit(1);
}

int main() {
    int sockfd;
    struct sockaddr_in recv_addr;
    char buffer[PACKET_SIZE];
    socklen_t addr_len = sizeof(recv_addr);
    double tsc_freq_mhz = get_tsc_freq_mhz();

    printf("CPU TSC frequency: %.2f MHz\n", tsc_freq_mhz);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(1);
    }

    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(PORT);
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    int cont = 0;
    for (int i = 0; i < 100; i++) {
    //while(1){
        ssize_t len = recvfrom(sockfd, buffer, PACKET_SIZE, 0,
                               (struct sockaddr *)&recv_addr, &addr_len);

        cont++;
        if (len >= sizeof(unsigned long long)) {
            unsigned long long send_ts, recv_ts;
            memcpy(&send_ts, buffer, sizeof(send_ts));
            recv_ts = __rdtsc();
            unsigned long long latency_cycles = recv_ts - send_ts;
            double latency_us = (double)latency_cycles / tsc_freq_mhz;

            printf("Packet %d: latency = %llu cycles (%.2f µs)\n",
                   /*cont*/ i, latency_cycles, latency_us);
        }
    }

    close(sockfd);
    return 0;
}

