#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"  // Change to the receiver's IP if needed
#define SERVER_PORT 8080
char MESSAGE[50];

int long long start;
int long long end;

static __always_inline volatile long long RDTSC() {
    
    //register long long TSC asm("eax");
    //asm volatile (".byte 15, 49" : : : "eax", "edx");
    //return TSC;

    unsigned int lo, hi;
    
    asm ("rdtsc" : "=a" (lo), "=d" (hi));         // Execute RDTSC and store results
    return ((long long)hi << 32) | lo;            // Combine high and low parts
} 


int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(server_addr);

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Server address setup
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    pid_t pid = getpid();
    char settar_cpuf[30];
    
    printf("Atribuindo processo para a CPU 5...\n");
    sprintf(settar_cpuf, "taskset -cp 5 %d", pid);
    system(settar_cpuf);


    int i = 0; 
    start = RDTSC();
    sprintf(MESSAGE, "Hello from UDP sender!%d", i);
    
    // Send UDP message
    for (i = 0; i < 1000; i++){
        
        //sprintf(MESSAGE, "Hello from UDP sender!%d", i);
        sendto(sockfd, MESSAGE, strlen(MESSAGE), 0,(struct sockaddr *)&server_addr,addr_len);
        //if (sendto(sockfd, MESSAGE, strlen(MESSAGE), 0,(struct sockaddr *)&server_addr,
        //            addr_len) < 0) {
        //    perror("Send failed");
        //    close(sockfd);
        //    exit(EXIT_FAILURE);
        //}
        
        //printf("UDP message sent: \"%s\"\n", MESSAGE);
    }
    end = RDTSC();
    
    //printf("UDP message sent: \"%s\"\n", MESSAGE);
    printf("### Valor final de RDTSC %lld ###\n", end - start);

    // Close socket
    close(sockfd);
    return 0;
}

