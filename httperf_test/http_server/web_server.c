#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#define PORT 8080
#define BUFFER_SIZE 4096

const char *response =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 47\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<html><body><h1>Hello from C server!</h1></body></html>";

int main() {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    char buffer[BUFFER_SIZE];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("HTTP server listening on port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        // Read and ignore request
        read(client_fd, buffer, BUFFER_SIZE);

        // Send simple HTTP response
        write(client_fd, response, strlen(response));

        close(client_fd);
    }

    close(server_fd);
    return 0;
}
