#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <float.h>
#include <netinet/in.h>

#define PORT 9000
#define PACKET_SIZE 64

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
    struct sockaddr_in recv_addr, accept_addr;
    char buffer[PACKET_SIZE];
    socklen_t addr_len = sizeof(recv_addr);
    double tsc_freq_mhz = get_tsc_freq_mhz();

    printf("CPU TSC frequencia: %.2f MHz\n", tsc_freq_mhz);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Criacao do socket falhou");
        exit(1);
    }

    // Set timeout for receiving response
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    //setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tv, sizeof(tv));
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));


    memset(&recv_addr, 0, sizeof(recv_addr));
    recv_addr.sin_family = AF_INET;
    recv_addr.sin_port = htons(PORT);
    recv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *)&recv_addr, sizeof(recv_addr)) < 0) {
        perror("bind falhou");
        exit(1);
    }

    if((listen(sockfd, 1)) != 0) { 
        printf("Listen falhou...\n"); 
        exit(0); 
    } 
    else
        printf("Server ouvindo..\n");

    socklen_t len_accept = sizeof(accept_addr);
    int connfd = accept(sockfd, (struct sockaddr *)&accept_addr, &len_accept ); 
    if (connfd < 0) { 
        printf("Erro server accept ...\n"); 
        exit(0); 
    } 
    else
        printf("Server accept passou...\n");

    /***********************************************************************************/
    float min=FLT_MAX, max=FLT_MIN; 

    int cont = 0, num_pkts = 1000;
    float latency[num_pkts];
    unsigned long long send_ts, recv_ts;

    for (int i = 0; i < /*num_pkts*/ 100; i++){
        //while(1){
        ssize_t len = recv(connfd, buffer, sizeof(buffer), /*MSG_WAITALL*/ 0); 

        cont++;
        if (len >= sizeof(unsigned long long)){
            memcpy(&send_ts, buffer, sizeof(send_ts));
            
            recv_ts = __rdtsc();
            
            unsigned long long latency_cycles = recv_ts - send_ts;
            double latency_us = (double)latency_cycles / tsc_freq_mhz;

            latency[cont] = latency_us;

            if (latency_us > max)
                max = latency_us;
            else if(latency_us < min)
                min = latency_us;

            printf("Packet %d: latencia = %llu ciclos (%.2f µs)\n",/*cont*/i, latency_cycles, latency_us);

            if(send(connfd, buffer, sizeof(buffer), 0) < 0){
                perror("Erro ao responder pkt");
            }
        }
    }

    float media_lat = media(latency, num_pkts);
    printf("\nLatency min/avg/max: %.3f/%.3f/%.3f ms\n", min, media_lat, max);


    close(sockfd);
    return 0;
    }

