#include "packet.h"
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>

// Define constants
#define MAX_PENDING_CONNECTIONS 5    // Maximum queued connections
#define BUFFER_SIZE 1024           // Size of receive buffer

// Global flag to track if server should continue running
volatile sig_atomic_t running = 1;

int server_fd;

// Signal handler for SIGINT (Ctrl+C)
void signal_handler(int signum) {
    if (signum == SIGINT) {
        //running = 0;
        close(server_fd);
        exit(0);
    }
}

int setup_server_socket(int port) {
    int opt = 1;
    struct sockaddr_in address;
    
    //if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0){
        perror("Erro ao criar socket");
        exit(EXIT_FAILURE);
    }

    if ( setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int) ) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);  
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_PENDING_CONNECTIONS) < 0) {
        perror("listen failed");
        close(server_fd);  
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

void handle_client(int client_fd, int num_packets, int latency_us) {
    char buffer[BUFFER_SIZE];
    int bytes_received;
    int packet_count = 0;

    printf("Starting packet processing...\n");

    while (packet_count < num_packets && running) {
        bytes_received = recv(client_fd, buffer, sizeof(packet_header), 0);
        
        if (bytes_received <= 0) {
            break;
        }

        packet_header* header = (packet_header*)buffer;
        
        char* payload = malloc(header->payload_size);
        if (!payload) {
            perror("Memory allocation failed");
            continue;
        }

        bytes_received = recv(client_fd, payload, header->payload_size, 0);
        if (bytes_received <= 0) {
            free(payload);
            break;
        }

        usleep(latency_us);

        char response[header->payload_size];
        sprintf(response, "Processed packet %d", header->sequence_number);
        send(client_fd, response, strlen(response), 0);

        free(payload);
        packet_count++;
    }

    printf("Finished processing %d packets\n", packet_count);
    close(client_fd);  
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        perror("Failed to set signal handler");
        return EXIT_FAILURE;
    }

    server_fd = setup_server_socket(8080);
    
    printf("Server ouvindo na porta 8080...\n");

    while (running) {
        client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        
        if (client_fd < 0 && errno != EINTR) {
            perror("accept failed");
            continue;
        }
        
        if (!running) {
            close(client_fd);
            break;
        }

        int config[2];
        if (recv(client_fd, config, sizeof(config), 0) <= 0) {
            close(client_fd);
            continue;
        }

        handle_client(client_fd, config[0], config[1]);
    }

    printf("\nShutting down server...\n");
    close(server_fd);
    return 0;
}
