// Realistic HTTP Server in C with latency, routing, logging, and threading
// gcc real_http_server.c -o real_http_server -lpthread
// ./real_http_server

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 8192
#define MAX_CONNECTIONS 100

void *handle_client(void *arg);
void log_request(const char *client_ip, const char *request_line, int status_code);
void simulate_latency();

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if ( setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int) ) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_CONNECTIONS) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("HTTP server listening on port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        pthread_t thread_id;
        int *pclient = malloc(sizeof(int));
        *pclient = client_fd;
        pthread_create(&thread_id, NULL, handle_client, pclient);
        pthread_detach(thread_id);
    }

    close(server_fd);
    return 0;
}

void *handle_client(void *arg) {
    int client_fd = *((int *)arg);
    free(arg);
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    int status_code = 200;

    int received = read(client_fd, buffer, BUFFER_SIZE - 1);
    if (received <= 0) {
        close(client_fd);
        return NULL;
    }
    buffer[received] = '\0';

    char method[8], path[1024];
    sscanf(buffer, "%7s %1023s", method, path);

    simulate_latency();

    // Determine response based on path
    const char *body;
    if (strcmp(path, "/") == 0) {
        body = "<html><body><h1>Welcome to the Home Page</h1></body></html>";
    } else if (strncmp(path, "/product", 8) == 0) {
        body = "<html><body><h1>Product Page</h1></body></html>";
    } else if (strncmp(path, "/error", 6) == 0) {
        body = "<html><body><h1>Internal Server Error</h1></body></html>";
        status_code = 500;
    } else {
        body = "<html><body><h1>404 Not Found</h1></body></html>";
        status_code = 404;
    }

    // Build HTTP response
    snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status_code,
        status_code == 200 ? "OK" : status_code == 404 ? "Not Found" : "Internal Server Error",
        strlen(body),
        body);

    write(client_fd, response, strlen(response));

    // Log the request
    log_request("127.0.0.1", path, status_code);

    close(client_fd);
    return NULL;
}

void log_request(const char *client_ip, const char *request_line, int status_code) {
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S %z", localtime(&now));
    printf("%s - - [%s] \"GET %s HTTP/1.1\" %d\n", client_ip, time_str, request_line, status_code);
}

void simulate_latency() {
    usleep(1000 + rand() % 5000); // Simulate 1-6ms delay
}
