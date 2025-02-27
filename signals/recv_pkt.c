#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define LISTEN_PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Falha ao criar Socket");
        exit(EXIT_FAILURE);
    }


    // Bind endereco e porta
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LISTEN_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Falha no Bind do Socket");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("UDP Receiver listening on port %d...\n", LISTEN_PORT);

//    ssize_t len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
//                   (struct sockaddr *)&client_addr, &client_len);
    
    ssize_t len;
    int i =0;
    for(i = 0; i< 1000; i++){

        if ( (len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_len)) < 0 ){
            perror("Receive failed");
        }
        
        printf("Received UDP message: \"%s\" %d\n", buffer, i);
    }


   //if (len < 0) {
   //     perror("Receive failed");
   // } else {
   //     buffer[len] = '\0';  // Null-terminate received message
   //     printf("Received UDP message: \"%s\"\n", buffer);
   // }

    close(sockfd);
    return 0;
}

