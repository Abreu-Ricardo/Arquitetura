#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <time.h>

#define SERVER_PORT 12345
#define PACKET_SIZE 64
#define PROCESSING_TIME_US 500  // Quantidade de microsecondos para processar

static __always_inline void simulate_processing() {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = PROCESSING_TIME_US * 1000; // Converte us to ns
    nanosleep(&ts, NULL);
}


int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buf[PACKET_SIZE];
    socklen_t addr_len = sizeof(client_addr);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        return 1;
    }

    printf("t_recebe esperando na porta %d...\n", SERVER_PORT);

    while (1) {
        ssize_t n = recvfrom(sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&client_addr, &addr_len);
        if (n < 0) {
            perror("recvfrom");
            return 1;
        }

        simulate_processing();

        // Envia o pacote de volta
        sendto(sockfd, buf, n, 0, (struct sockaddr *)&client_addr, addr_len);
    }

    close(sockfd);
    return 0;
}
