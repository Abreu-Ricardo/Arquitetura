#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <errno.h> // todos os retornos de erro ficam armazenados em errno

//#include "vmlinux.h"

#include "sigsnoop.skel.h"
#include "signal_monitor.skel.h"
#include "teste_tc.skel.h"

int main(int argc, char** argv){
    
   printf("Carregando programa...\n");
    struct sigsnoop_bpf *skel;
    struct teste_tc *skell;
   
    //int create = teste_tc__create_skeleton(skell);
    //int ret_create = teste_tc__create_skeleton(skell); 
    
    //skell = teste_tc__open();
    //skell = teste_tc__open_and_load();
    skel = sigsnoop_bpf__open_and_load();
    if (!skel){
        perror("\nProblema em abrir e carregar o programa...");
        return 1;
    }
    printf("Programa carregado!\n");

    //int ret_attach = teste_tc__attach(skell);
    int ret_attach = sigsnoop_bpf__attach(skel);
    if(ret_attach < 0 ){
        printf("Erro ao acoplar o programa...\n");
    }

    printf("Abriu, carregou, acoplou e entrou no loop...");
    while (1){
        ;
    }
    

    return 0;
}
