#include "http.h"
#include "xsk_kern.skel.h"
#include <xdp/xsk.h>
#include <xdp/libxdp.h>



struct xsk_kern_bpf *skel = NULL;
char path[256]; 

void clean_bpf(int signum){

    bpf_object__unpin_maps(skel->obj, path);
    xsk_kern_bpf__detach(skel);
    xsk_kern_bpf__destroy(skel);

    printf("\nRemovendo o programa eBPF...\n");
    exit(0);
}


/***********************************/

void imprime_mapa(int fd_mapa_sinal, int nf_id){

    pid_t temp;

    for(uint32_t i=0; i <= nf_id; i++){

        if ( bpf_map_lookup_elem(fd_mapa_sinal, &i, &temp) < 0 ){ 
            perror("Erro ao consultar o mapa eBPF"); 
            continue; 
        }

        printf("mapa_sinal[%d]: %d\n", /*nf_id*/i, temp);
    }

    return;
}

/***********************************/

void cria_sigshared_mem(int fd_sigshared_mem, int tam_sigshared){

    fd_sigshared_mem = shm_open(SIGSHARED_NAME, O_CREAT | O_RDWR, 0777);
    if (fd_sigshared_mem < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    int ret_ftruncate = ftruncate(fd_sigshared_mem, tam_sigshared); 
    if ( ret_ftruncate == -1 ){
        perror("ERRO NO ftruncate()");
        exit(1);  
    }


    sigshared_ptr   = ( void *) mmap(0, tam_sigshared, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
}



/***********************************/
int main(int argc, char **argv){

    signal(SIGINT, clean_bpf);

    skel = xsk_kern_bpf__open_and_load();
    if(skel == NULL){
        perror("ERRO AO ABRIR programa");
        exit(1);
    }

    xsk_kern_bpf__attach(skel);
    //skel->links.xdp_prog = bpf_program__attach_xdp(skel->progs.xdp_prog, 2/*ifindex*/);

    char *dir_temp = getenv("SIGSHARED");
    
    strcpy( path, dir_temp);
    strcat( path, "/dados"); 
    printf("PATH: %s\n", path);

    //bpf_map__pin(skel->maps.mapa_sinal, path);
    bpf_object__pin_maps(skel->obj, path);


    //signal(SIGINT, clean_bpf);
    /*********************************************************/
    int pid = getpid();
    int key = 0;
    bpf_map_update_elem(bpf_map__fd(skel->maps.mapa_sinal), &key, &pid, BPF_ANY);
    
    sigshared_ptr = NULL;
    int fd_sigshared_mem;
    int tam_sigshared = sizeof(struct http_transaction) * 5;

    cria_sigshared_mem(fd_sigshared_mem, tam_sigshared);

    sigset_t set;
    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGRTMIN+1); 
    sigaddset(&set, SIGRTMIN+2);            
    sigprocmask(SIG_BLOCK, &set, NULL); 

    int sigrtmin1 = 35;
    int next_nf = 1;
    int pid_alvo = -1;
    siginfo_t data_rcv; 
    sigval_t data_send; 

    printf("Digite qualquer tecla quando as outras nfs terminarem de salvar os PID's no mapa eBPF...\n");
    getchar();

    printf("PID: %d\n", pid);
    imprime_mapa(bpf_map__fd(skel->maps.mapa_sinal), 3);

    printf("Esperando gatilho para enviar o sinal...\n");
    //while( sigwait(&set, &sigrtmin1) == 0 ){
    if( sigwait(&set, &sigrtmin1) == 0 ){
   
        printf("--> Recebeu sinal\n");
        // fazer consulta no mapa ebpf para pegar o PID
        bpf_map_lookup_elem(bpf_map__fd(skel->maps.mapa_sinal), &next_nf, &pid_alvo);
        data_send.sival_int = next_nf;
        
        if(sigqueue(pid_alvo, SIGRTMIN+1, data_send) < 0){
                perror("Erro ao enviar sinal");
        }

    }

    struct http_transaction *txn;
    txn = (struct http_transaction *) sigshared_ptr;

    for(int i=0; i< 5; i++){

        printf("contador[%d]: %d\n", i, txn[i].contador_containers );
        printf("Mensagem[%d]: %s\n", i, txn[i].msg_shm );
        printf("\n\n");

    }


    return EXIT_SUCCESS;
}
