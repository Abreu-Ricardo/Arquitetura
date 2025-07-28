#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <float.h>

#include <x86intrin.h>

#define PORT 9000
//#define DEST_IP "127.0.0.1"
#define DEST_IP "20.20.20.2"
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
float media(float vetor[], int tam){
    float result, soma = 0;

    for(int i = 0; i < tam; i++)
        soma += vetor[i];

    result = soma / (float)tam;
    return result;
}
/******************************************************/
/****************************************************************************/
int main(int argc, char **argv){
    
    if(argc < 3){
        printf("Passe os parametros: %s <IP> <NUM_PKTS>\n", argv[0]);
        exit(-1);
    }
    
    char *dest = argv[1];
    int num_pkts = atoi(argv[2]);
    int sockfd;
    struct sockaddr_in dest_addr;
    char buffer[PACKET_SIZE];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket failed");
        exit(1);
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, dest, &dest_addr.sin_addr);


    if (connect(sockfd, (struct sockaddr *)&dest_addr, sizeof(dest_addr))
            != 0) {
        printf("Erro na conexao com o servidor...\n");
        exit(0);
    }
    else
        printf("Conectado com o servidor..\n");


    /***************************************************************/
    
    unsigned long long inicio, fim;

    float min=FLT_MAX, max=FLT_MIN;
    ssize_t len;
    float latency_us, latency[num_pkts];

    for (int i = 0; i < num_pkts; i++) {
        unsigned long long ts = __rdtsc();
        memcpy(buffer, &ts, sizeof(ts)); // put timestamp in the beginning
                                         
         inicio = RDTSC();
        //inicio = __rdtsc();
        send(sockfd, buffer, PACKET_SIZE, 0);

        fim = RDTSC();
        len = recv(sockfd, buffer, PACKET_SIZE, 0);
        
        //fim = __rdtsc();
        //fim = RDTSC();

        // Pegar ciclos
        latency_us = (fim - inicio);
        
        // Pegar latencia em us
        //latency_us = (fim - inicio) / 3600.0;
        latency[i] = latency_us;
        
        if(len > 0){
            if (latency_us > max)
                max = latency_us;
            else if(latency_us < min)
                min = latency_us;
        }
        
        printf("Packet(%d): latency %.2f µs\n", i, latency_us);
        usleep(10000); // 10ms delay
    }

    float avg = media(latency, num_pkts);
    printf("\nLatency min/avg/max: %.3f/%.3f/%.3f ms\n", min, avg, max);

    close(sockfd);
    return 0;
}

