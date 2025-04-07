#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <errno.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "sigsnoop.skel.h" // Generated by bpftool or libbpf
#include "teste_tc.skel.h" // Generated by bpftool or libbpf

char *cria_qdisc         = "sudo tc qdisc  add dev enp0s3 clsact";
char *carrega_tc_egress  = "sudo tc filter add dev enp0s3 egress  bpf direct-action obj teste_tc.bpf.o sec tc";
char *carrega_tc_ingress = "sudo tc filter add dev enp0s3 ingress bpf direct-action obj teste_tc.bpf.o sec tc";
char *remove_tc          = "sudo tc qdisc  del dev enp0s3 clsact";

struct teste_tc_bpf *tc_skel;

void pega_sinal(int signum){

	if (signum == SIGINT){
		system(remove_tc);
		printf("\nPrograma removido TC\n");

		teste_tc_bpf__destroy(tc_skel);
		exit(0);
	}

	else if(signum == SIGUSR1){
		printf("Recebi o sinal!!\n");
	}

}

/***********************************************************/                           
int main(int argc, char **argv){
    struct sigsnoop_bpf *skel;

    signal(SIGINT, pega_sinal);
    signal(SIGUSR1, pega_sinal);

    //struct teste_tc_bpf *tc_skel;
    
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    
    //skel = sigsnoop_bpf__open_and_load();
    //if ( !skel ){
    //    perror("Erro ao abrir e carregar o skeleton do programa");
    //    sigsnoop_bpf__destroy(skel);
    //    exit(1);
    //}

    //int ret_attach = sigsnoop_bpf__attach(skel);
    //if (ret_attach){
    //    perror("Erro ao aclopar programa");
    //    sigsnoop_bpf__destroy(skel);
    //    exit(1);
    //}


    tc_skel = teste_tc_bpf__open_and_load();
    if ( !tc_skel ){
        perror("Erro ao abrir e carregar o skeleton do programa");
        teste_tc_bpf__destroy(tc_skel);
        exit(1);
    }

    // Cria qdisc e carrega programa eBPF com a ferramenta a ip do iproute2
    system(cria_qdisc);
    system(carrega_tc_ingress);

    pid_t pid = getpid();
    __u32 valor_pego = -1;
    __u32 key=0;
    int fd_map = -1;

    if ( ( fd_map = bpf_object__find_map_fd_by_name( tc_skel->obj , "valores") ) < 0 ){
    	perror("Erro ao pegar o mapa!");
	pega_sinal(SIGINT);
    }


    //__u32 ret_lookup = bpf_map__update_elem( tc_skel->maps.valores, &key, sizeof(key), &pid, sizeof(pid), 0 );
    __u32 ret_lookup = bpf_map_update_elem( fd_map, &key,  &pid, BPF_ANY );


    if (ret_lookup < 0){
    	printf("Erro ao atualizar o mapa\n");
    }



    printf("\nCtrl+C para parar\nxxx Programa carregado e aclopado xxx \n");

    while(1){  ;}

    return 0;
}
