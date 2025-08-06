#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>


int ant = -1;
int cont_sin = 0;

#include "xsk_kern.skel.h"

void siguser(int signum){

    //if (signum == 10 && cont_sin > ant){
    if (signum == SIGRTMIN+1 && cont_sin > ant){
        ant = cont_sin;
        cont_sin++;
        //printf("Recebeu sinal SIGUSR1(%d): %d!\n", signum, ++cont_sin);
    }
    else if(signum == 2){
        printf("Recebi um sinal de SIGINT(%d), ate mais...\n", signum);
        printf("Sinais recebidos: %d\n", cont_sin);
        exit(1);
    }
    else{
        printf("Perdeu um sinal! %d\n", signum);
        exit(1);
    }

    //cont_sin++;
}


/****************************************************/
void clean(struct xsk_kern_bpf *skel){
    xsk_kern_bpf__destroy(skel);
    exit(1);
}

/****************************************************/
int main(){

    struct xsk_kern_bpf *skel;
    skel = xsk_kern_bpf__open_and_load();
    if (!skel){ 
        printf("Erro ao carregar programa\n"); 
        clean(skel);
    }
    
    int ifindex = 2;
    skel->links.xdp_prog = bpf_program__attach_xdp( skel->progs.xdp_prog , ifindex );
    int mapa_fd = bpf_object__find_map_fd_by_name( skel->obj, "mapa_sinal");
    if (mapa_fd < 0) {
        printf("Erro ao tentar obter o fd do mapa pelo bpf_obj, retorno: %d\n", mapa_fd);
        clean(skel);
    }

    int key=0;
    int pid = getpid();
    bpf_map_update_elem( bpf_map__fd(skel->maps.mapa_sinal) , &key, &pid, BPF_ANY);
    //bpf_object__pin_maps( skel->obj , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados");

    //int ret_attach = xsk_kern_bpf__attach(skel);
    //if(ret_attach < 0){ 
    //    printf("Erro ao aclopar programa eBPF\n");
    //    clean(skel);
    //}

    // Capta sinal de SIGUSR1(valor 10)
    signal( SIGINT , siguser);
    //signal( SIGUSR1, siguser);
    
    struct sigaction sigact;
   
    FILE *fp = popen("xclip -selection clipboard", "w");
    if (fp == NULL) {
        perror("popen failed");
        return 1;
    }

    int PID = getpid();
    char txt[10];

    // Poe o pid no clipboard ja
    sprintf(txt, "%d", PID);  // converte para string
    fprintf(fp, "%s", txt);
    pclose(fp);

    printf("Entrando no loop de espera...\nPID do processo %d copiado para o clipboard!\n", PID);
    printf("Ouvindo o sinal: %d...\n", SIGRTMIN+1);

    sigset_t set; 
    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    //sigaddset(&set, SIGUSR1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q ode "ouvir"
    sigaddset(&set, SIGRTMIN+1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q ode "ouvir"
    sigprocmask(SIG_BLOCK, &set, NULL);  // Aplica o conjunto q pode "ouvir"

    int sig_user1=10, sigrtmin1 = SIGRTMIN+1;
    int cont=0;

    while( sigwait(&set, &sigrtmin1) >= 0 ){
        printf("cont = %d\n", ++cont);
        siguser(sigrtmin1);
    }

    return 0;
}
