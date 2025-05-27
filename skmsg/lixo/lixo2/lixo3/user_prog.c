#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAP_NAME "sockhash_map"

int create_connected_socket(int port, int is_server) {
    int sock;
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    if (is_server) {
        bind(sock, (struct sockaddr *)&addr, sizeof(addr));
        listen(sock, 1);
        int client = accept(sock, NULL, NULL);
        close(sock); // Close the listening socket
        return client;
    } else {
        // Give the server some time to start listening
        sleep(1);
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("connect");
            exit(1);
        }
        return sock;
    }
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, map_fd;
    int sock1_fd, sock2_fd;
    __u32 key0 = 0, key1 = 1;

    // Load the BPF object file
    obj = bpf_object__open_file("sk_msg_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open eBPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load eBPF object\n");
        return 1;
    }

    // Find the program and map
    prog = bpf_object__find_program_by_name(obj, "redirect_sk_msg");
    if (!prog) {
        fprintf(stderr, "Couldn't find sk_msg program\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);
    map_fd = bpf_object__find_map_fd_by_name(obj, MAP_NAME);
    if (map_fd < 0) {
        fprintf(stderr, "Couldn't find map\n");
        return 1;
    }

    // Create two connected TCP sockets
    pid_t pid = fork();
    if (pid == 0) {
        // Child: client
        sock2_fd = create_connected_socket(12345, 0); // client
        pause(); // Hold the socket open
        return 0;
    } else {
        // Parent: server
        sock1_fd = create_connected_socket(12345, 1); // server
        sleep(1); // wait a moment for client
    }

    // Insert sockets into the sockhash
    if (bpf_map_update_elem(map_fd, &key0, &sock1_fd, BPF_ANY)) {
        perror("map_update key0");
        return 1;
    }

    if (bpf_map_update_elem(map_fd, &key1, &sock1_fd, BPF_ANY)) {
        perror("map_update key1");
        return 1;
    }

    // Attach the program to sock1_fd
    if (bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT, 0)) {
        perror("bpf_prog_attach");
        return 1;
    }

    printf("BPF program attached. Try sending data.\n");
    write(sock1_fd, "hello", 5);

    sleep(2); // Give time for messages to be redirected

    return 0;
}
