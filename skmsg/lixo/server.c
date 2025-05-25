#include "packet.h"
#include "ebpf.skel.h"

    struct sock_key key = {
        .sip    = LOCALHOST_IPV4,
        .dip    = LOCALHOST_IPV4,
        .sport  = SERVER_PORT,
        .dport  = SERVER_PORT,
        .family = AF_INET,
    };

int main(void) {
    
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("Erro ao configurar limite de memória bloqueada");
        exit(1);
    }


    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Create server socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket creation failed");
        exit(1);
    }

    // Set address reuse option
    int optval = 1;
    if ( setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0){
        perror("Erro no setsockopt");
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if( inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr)) <= 0 ){
        perror("Erro no inet_pton");
    }

    // Bind socket to address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(1);
    }

    // Listen for connections
    if (listen(server_fd, MAX_Pending) < 0) {
        perror("listen failed");
        exit(1);
    }

    printf("Server listening on port %d...\n", SERVER_PORT);

    struct ebpf *skel;
    skel = ebpf__open_and_load();

    int prog_fd = bpf_program__fd( skel->progs.bpf_redir );
    int map_fd  = bpf_map__fd( skel->maps.sock_ops_map);

    int err = bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT, 0);
    if (err < 0) {
        printf("AQUI %d\n", map_fd);
        perror("bpf_prog_attach");
        return 1;
    }

    int chave = 0;
    //if (bpf_map_update_elem(map_fd, &key, &server_fd, BPF_ANY)) {
    if (bpf_map_update_elem(map_fd, &chave, &server_fd, BPF_ANY)) {
        perror("Failed to register socket");
        exit(1);
    }

    // Accept and handle connections
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        char buffer[1024];
        ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer), 0);
        
        if (bytes_received <= 0) {
            break;
        }
        
        printf("Received: %s\n", buffer);
        
        char* message = "Message received by server\n";
        send(client_fd, message, strlen(message), 0);
    }

    close(client_fd);
    close(server_fd);
    return 0;
}
