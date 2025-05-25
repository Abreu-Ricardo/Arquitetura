#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define SOCK_MAP_KEY 1

#include "kern_teste_sk.skel.h"

int main() {
    struct bpf_object *obj;
    int prog_fd, map_fd;
    int sock1, sock2;
    int err;

    //struct kern_teste_sk_bpf *skeleton;
    //skeleton = kern_teste_sk_bpf__open_and_load();
    //if (skeleton == NULL){
    //    printf("errro ao abrir o programa kern.bpf.o\n");
    //}
    //int ret_attach = kern_teste_sk_bpf__attach(skeleton);

    int listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        //.sin_port = htons(12345),
        .sin_port = htons(12345),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if ( bind(listener_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        perror("erro no bind");
    }


    //skeleton->links.bpf_sock_msg_redirect = bpf_program__attach_sockmap(skeleton->progs.bpf_sock_msg_redirect, bpf_map__fd(skeleton->maps.sock_hash_map));
    //skeleton->links.bpf_sock_msg_redirect = bpf_program__attach_sockmap(skeleton->progs.bpf_sock_msg_redirect, bpf_map__fd(skeleton->maps.sock_hash_map));

    //if (skeleton->links.bpf_sock_msg_redirect == NULL){
    //    printf("Erro no bpf_program__attach_sockmap\n");
    //    kern_teste_sk_bpf__detach(skeleton);
    //    kern_teste_sk_bpf__destroy(skeleton);
    //}

    // Load BPF program
    obj = bpf_object__open_file("kern_teste_sk.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        perror("Failed to open BPF object");
        return 1;
    }

    bpf_object__load(obj);

    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(obj, "bpf_sock_msg_redirect"));
    map_fd  = bpf_object__find_map_fd_by_name(obj, "sock_hash_map");

    //prog_fd = bpf_program__fd( skeleton->progs.bpf_sock_msg_redirect); 
    //map_fd  = bpf_map__fd( skeleton->maps.sock_hash_map );

    if (prog_fd < 0 || map_fd < 0) {
        fprintf(stderr, "Failed to find prog or map fd\n");
        return 1;
    }

    // Create sockets
   // int pair[2];
   // if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) {
   //     perror("socketpair");
   //     return 1;
   // }

   // sock1 = pair[0];
   // sock2 = pair[1];


    listen(listener_fd, 1);

    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if ( connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ){
        perror("erro no connect");
    }

    int server = accept(listener_fd, NULL, NULL);
    err = bpf_prog_attach(prog_fd, map_fd, BPF_SK_MSG_VERDICT, 0);
    if (err < 0) {
        printf("AQUI %d\n", map_fd);
        perror("bpf_prog_attach");
        return 1;
    }
    // Add destination socket to sockhash
    //__u32 key = SOCK_MAP_KEY;
    __u32 key = 0;
    err = bpf_map_update_elem(map_fd, &key, &client_fd, BPF_ANY);
    if (err) {
        perror("bpf_map_update_elem");
        return 1;
    }

    // Attach sk_msg program to source socket
    //err = bpf_prog_attach(prog_fd, listener_fd, BPF_SK_MSG_VERDICT, 0);
    //while(1){
    //    ;
    //}

    // Test sending a message from sock1 (should be redirected to sock2)
    const char *msg = "hello via ebpf";
    send(listener_fd, msg, strlen(msg), 0);

    char buf[128] = {};
    recv(client_fd, buf, sizeof(buf), 0);

    printf("sock2 received: %s\n", buf);

    // Cleanup
    close(listener_fd);
    close(client_fd);
    bpf_object__close(obj);

    return 0;
}
