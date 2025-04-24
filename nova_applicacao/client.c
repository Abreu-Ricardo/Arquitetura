#include "packet.h"
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

//#define DEFAULT_SERVER_IP "127.0.0.1"
#define DEFAULT_SERVER_IP "10.10.10.2"

int main(int argc, char const *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    int num_packets, latency_us;
    
    // Get configuration from command line arguments
    if (argc != 3) {
        printf("Usage: ./client <num_packets> <latency_microseconds>\n");
        return 1;
    }
    
    num_packets = atoi(argv[1]);
    latency_us = atoi(argv[2]);

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8080);

    // Convert IPv4 address from string to binary format
    if(inet_pton(AF_INET, DEFAULT_SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connection failed");
        exit(EXIT_FAILURE);
    }

    // Send configuration
    int config[2] = {num_packets, latency_us};
    send(sock, config, sizeof(config), 0);

    // Send packets
    for (int i = 0; i < num_packets; i++) {
        packet_header header;
        header.sequence_number = i;
        header.payload_size = 256; // Fixed payload size example

        // Send header
        send(sock, &header, sizeof(header), 0);

        // Send payload
        char payload[header.payload_size];
        sprintf(payload, "Packet %d content", i);
        send(sock, payload, header.payload_size, 0);

        // Receive and print response
        char response[header.payload_size];
        recv(sock, response, header.payload_size, 0);
        printf("Response: %s\n", response);

        // Add delay between packets
        usleep(latency_us);
    }

    close(sock);
    return 0;
}
