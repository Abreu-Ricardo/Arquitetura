#include "packet.h"
#include "ebpf.skel.h"
#include <string.h>

struct ebpf *skel;
struct sock_key key = {
    .sip    = LOCALHOST_IPV4,
    .dip    = LOCALHOST_IPV4,
    .sport  = SERVER_PORT,
    .dport  = SERVER_PORT,
    .family = AF_INET,
};

void capta_sinal(int signum){
    
    if (signum == SIGINT){
        bpf_map__unpin( skel->maps.sock_ops_map , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/sock_ops_map");
        bpf_map__unpin( skel->maps.temp , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/temp");
    }

    ebpf__detach(skel);
    ebpf__destroy(skel);
    close(server_fd);
    close(client_fd);

    system("rm ../../dados/ebpf*");

    exit(0);
}


int main(void) {
    
    signal( SIGINT , capta_sinal);

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("Erro ao configurar limite de memória bloqueada");
        exit(1);
    }


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
    //if( inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr)) <= 0 ){
    if( inet_pton(AF_INET, "10.10.10.1", &(server_addr.sin_addr)) <= 0 ){
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


    skel = ebpf__open_and_load();

    bpf_object__pin_maps( skel->obj , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados");

    int prog_fd = bpf_program__fd( skel->progs.bpf_redir );
    int map_fd  = bpf_map__fd( skel->maps.sock_ops_map);

    int err = bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT, 0);
    if (err < 0) {
        printf("AQUI %d\n", map_fd);
        perror("bpf_prog_attach");
        return 1;
    }

    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("accept failed");
        //continue;
    }

    int chave = 0;
    //if (bpf_map_update_elem(map_fd, &key, &server_fd, BPF_ANY)) {
    if ( bpf_map_update_elem(map_fd, &chave, &client_fd, BPF_ANY) < 0) {
        perror("Erro ao atualizar o mapa com o FD do socket");
        exit(1);
    }

/*************************************************/
    char buffer[1024];
    char *message = "Ola do servidor";
    //strcpy(buffer, message);
/*************************************************/


    struct iovec rcv_iov = {
        .iov_base = buffer,
        .iov_len = sizeof(buffer)
    };
    struct msghdr rcv_msg = {
        .msg_name    = NULL,
        .msg_namelen = 0,
        .msg_iov     = &rcv_iov,
        .msg_iovlen  = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags   = 0
    };

    struct iovec send_iov = {
        .iov_base = buffer,
        .iov_len  = sizeof(buffer)
    };

    struct msghdr send_msg = {
        .msg_name    = NULL,
        .msg_namelen = 0,
        .msg_iov     = &send_iov,
        .msg_iovlen  = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags   = 0
    };
/*************************************************/

    // Accept and handle connections
    while (1) {

        //ssize_t bytes_received = recv(client_fd, buffer, sizeof(buffer), 0);
        ssize_t bytes_received = recvmsg(client_fd, &rcv_msg, 0);
        
        if (bytes_received <= 0) {
            printf("BYTES RECEBIDOS: bytes_received <= 0\n");
            break;
        }
        
        //printf("Received: %s\n", buffer);
        char temp[200];
        strcpy(temp, rcv_msg.msg_iov->iov_base);
        //printf("Received: %s\n", (char *)rcv_msg.msg_iov->iov_base);
        printf("Received: %s\n", temp);
        memset( rcv_msg.msg_iov->iov_base, 0, sizeof(buffer));
        memset( temp, 0, sizeof(temp));
        
        char *message = "Message received by server\n";
        send_msg.msg_iov->iov_base = message;
        send_msg.msg_iov->iov_len  = sizeof(*message);
        //send(client_fd, message, strlen(message), 0);
        
        int ret_sendmsg = sendmsg(client_fd, &send_msg, 0);
        if ( ret_sendmsg < 0 ){
            printf("Valor %d\n", ret_sendmsg);
            perror("Erro no sendmsg()");
        }
    }
    
    capta_sinal(SIGINT);
    //close(client_fd);
    //close(server_fd);
    
    return 0;
}
