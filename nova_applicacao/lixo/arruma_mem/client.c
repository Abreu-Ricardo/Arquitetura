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
#include <float.h>

#define SERVER_PORT 12345
#define CLIENT_PORT 54321  // Must match what server replies to
#define BUF_SIZE 2048

//double time_diff_ms(struct timespec start, struct timespec end) {
//    return (end.tv_sec - start.tv_sec) * 1000.0 +
//           (end.tv_nsec - start.tv_nsec) / 1.0e6;
//}

static __always_inline volatile long long RDTSC(){

    //register long long TSC asm("eax");
    //asm volatile (".byte 15, 49" : : : "eax", "edx");
    //return TSC;

    unsigned int lo, hi;

    asm ("rdtsc" : "=a" (lo), "=d" (hi)); // Execute RDTSC and store results
    return ((long long)hi << 32) | lo;    // Combine high and low parts
}

/******************************************************/
double time_diff_ms(long long int start, long long int end){
    // 3600    --> para us
    // 3600000 --> para ms
    return (double)(end - start) / 3600000.0;
}

/******************************************************/
float media(float vetor[], int tam){
    float result, soma = 0;

    for(int i = 0; i < tam; i++)
        soma += vetor[i];

    result = soma / (float)tam;
    return result;
}
/******************************************************/
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "%s <server_ip> <num_packets>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    long long int inicio, fim;
    
    char settar_cpup[30]; 
    sprintf(settar_cpup, "taskset -cp 3 %d", getpid());
    system(settar_cpup);

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

    // Var para usar nas metricas
    float min=FLT_MAX, max=FLT_MIN;
    float *latency_pkts = {0};
    latency_pkts = (float *) malloc( sizeof(float) * num_packets );

    //const char *msg = "Request (raw)";
    const char msg[20] = "Request (cru)";
    struct timespec start, end;
    int len;
    double latency;
    
    // Laco de envio dos pkts
    for (int i = 0; i < num_packets; i++) {
        //clock_gettime(CLOCK_MONOTONIC, &start);
        inicio = RDTSC();

        if (sendto(sockfd, msg, /*strlen(msg)*/ sizeof(msg), 0,
                   (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("sendto failed");
            continue;
        }

        //len = recvfrom(sockfd, buffer, BUF_SIZE, 0, NULL, NULL);
        len = recvfrom(sockfd, buffer, BUF_SIZE, MSG_WAITALL, NULL, NULL);
        //clock_gettime(CLOCK_MONOTONIC, &end);
        fim = RDTSC();

        if (len > 0) {
            buffer[len] = '\0';
            //latency = time_diff_ms(start, end);
            latency = time_diff_ms(inicio, fim);

            if (latency > max)
                max = latency;
            else if(latency < min)
                min = latency;

            latency_pkts[i] = latency;
            printf("Reply %d: %s | Latency: %.3f ms\n", i + 1, buffer, latency);

        } else {
            perror("Timeout or receive error");
            //close(sockfd);
            //exit(1);
        }
        usleep(120);
    }

    float media_lat = media(latency_pkts, num_packets);
    printf("Latency min/avg/max: %.3f/%.3f/%.3f ms\n", min, media_lat, max);
    
    close(sockfd);
    return 0;
}

