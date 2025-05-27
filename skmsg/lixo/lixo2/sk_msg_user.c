#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>

#include <signal.h>

#define KEY 1

int main() {
    struct bpf_object *obj;
    int prog_fd, load_prog_fd, map_fd;

    // OPEN & LOAD
    obj = bpf_object__open_file("sk_msg_kern.o", NULL);
    if (!obj) {
        perror("bpf_object__open_file");
        return 1;
    }
    if ( bpf_object__load(obj) < 0) {
        perror("erro no bpf_objext__load");
        exit(1);
    }

    struct bpf_program *prog = bpf_object__find_program_by_name( obj , "bpf_sock_msg_redirect");
    
    // MAP
    prog_fd = bpf_program__fd(prog);
    map_fd = bpf_object__find_map_fd_by_name(obj, "sock_map");
    int test_map_fd = bpf_object__find_map_fd_by_name(obj, "test_map");

    // Socket TCP
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
        //.sin_addr.s_addr = inet_addr("10.10.10.1"),
        .sin_port = htons(12345),
    };

    // reusar porta e socket
    int opt = 1;
    if ( setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Erro no setsockopt");
        exit(1);
    }

    if(bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        perror("Erro no bind");
        exit(1);
    }

    if( listen(server_fd, 1) < 0){
        perror("erro no listen");
        exit(1);
    }

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if( connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        perror("Erro no connect");
        exit(1);
    }


    socklen_t server_len = sizeof(addr);
    //__u64 conn_fd = accept(server_fd, NULL, NULL);
    __u64 conn_fd = accept(server_fd, (struct sockaddr *)&addr, &server_len);
    printf("Valor do conn_fd: %lld server_fd: %d\n", conn_fd, server_fd);

    if (conn_fd < 0){
    	perror("erro no accept");
        exit(1);
    }

    //bpf_object__pin_maps( obj, "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados");

    __u32 chave = 0;
    // Insert conn_fd into sockhash
    //bpf_map_update_elem(map_fd, &KEY, &conn_fd, BPF_ANY);
    if ( bpf_map_update_elem(map_fd, &chave, &conn_fd, BPF_ANY) < 0){
        perror("Erro no bpf_map_update_elem");
        exit(1);
    }

    if ( bpf_map_update_elem(test_map_fd, &chave, &conn_fd, BPF_ANY) < 0){
        perror("Erro no bpf_map_update_elem do test");
        exit(1);
    }

    //if (bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT, 0)) {
    if (bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT, 0) < 0) {
        perror("bpf_prog_attach");
        exit(1);
    }

    //for (int i =0; i< 10; i++){
        // Send data from client to be redirected to conn_fd
        const char *msg = "Hello via eBPF!";
        send(client_fd, msg, strlen(msg), 0);

        char buf[128];
        int n = recv(conn_fd, buf, sizeof(buf) - 1, 0);
        buf[n] = '\0';
        printf("Server received: %s\n", buf);
    //}

    pause();

    close(client_fd);
    close(conn_fd);
    close(server_fd);
    bpf_object__close(obj);
    system("rm ../../../dados/sk_kern");
    system("rm ../../../dados/sock_map");
    system("rm ../../../dados/test_map");
    
    return 0;
}
