#include "http.h"
#include "xsk_kern.skel.h"
#include <xdp/xsk.h>
#include <xdp/libxdp.h>



struct xsk_kern_bpf *skel = NULL;

void cria_sigshared_mem(int fd_sigshared_mem, int tam_sigshared){

    fd_sigshared_mem = shm_open(SIGSHARED_NAME, O_CREAT | O_RDWR, 0777);
    if (fd_sigshared_mem < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }


    sigshared_ptr   = ( void *) mmap(0, tam_sigshared, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
    printf("Memoria compartilhada acessada...\n");
}


/***********************************/

void imprime_mapa(int fd_mapa_sinal, int nf_id){

    pid_t temp;

    printf("nf_id %d\n", nf_id);

    for(uint32_t i=0; i <= nf_id; i++){

        //printf("Iteracao: %d\n", i);
        if ( bpf_map_lookup_elem(fd_mapa_sinal, &i, &temp) < 0 ){ 
            perror("Erro ao consultar o mapa eBPF"); 
            continue; 
        }

        printf("mapa_sinal[%d]: %d\n", /*nf_id*/i, temp);
        fflush(stdout);
        //i++;
    }

    return;
}

/***********************************/

int main(int argc, char **argv){

    if (argc < 2){
        printf("Passe o id da nf: ./%s nf_id\n", argv[0]);
        return EXIT_FAILURE;
    } 

    char path[256]; 
    char *dir_temp = getenv("SIGSHARED");
    
    strcpy( path, dir_temp);
    strcat( path, "/dados"); 

    strcat( path, "/mapa_sinal"); 
    printf("PATH: %s\n", path);
    int fd_mapa_sinal =  bpf_obj_get(path);
    if ( fd_mapa_sinal < 0){
        perror("Erro ao pegar FD do mapa");
        exit(1);
    }


    pid_t pid = getpid();
    uint32_t nf_id = atoi(argv[1]);
    printf("Atualizando mapa eBPF com pid: %d e com chave NF:%d\n", pid, nf_id);
    //bpf_map_update_elem(bpf_map__fd(skel->maps.mapa_sinal), &nf_id, &pid, BPF_ANY);
    if (bpf_map_update_elem(fd_mapa_sinal, &nf_id, &pid, BPF_ANY) < 0){
        perror("Erro ao atualizar mapa eBPF");
        exit(1);
    }
    
    sigshared_ptr = NULL;
    int fd_sigshared_mem;
    int tam_sigshared = sizeof(struct http_transaction) * 5;

    cria_sigshared_mem(fd_sigshared_mem, tam_sigshared);

    int sigrtmin1 = SIGRTMIN+1;
    
    siginfo_t data_rcv; 
    sigval_t data_send; 
    sigset_t set;
   
    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGRTMIN+1);            
    sigprocmask(SIG_BLOCK, &set, NULL); 

    int next_nf = nf_id+1;
    int pid_alvo;

    imprime_mapa(fd_mapa_sinal, nf_id);

    struct http_transaction *txn;
    void *ptr;

    printf("\n==NF%d== Esperando sinal...\n", nf_id);
    while(sigwaitinfo(&set, &data_rcv) ){
        
        int addr = data_rcv.si_int;
        //struct http_transaction *txn = (struct http_transaction *) sigshared_ptr;

        //txn = /*(struct http_transaction *)*/ sigshared_ptr;
        ptr = /*(struct http_transaction *)*/ sigshared_ptr;
        ptr += (sizeof(struct http_transaction) * addr);
        txn = (struct http_transaction *)ptr;

        printf("MSG: %s\nContador: %d\n", txn->msg_shm, txn->contador_containers);

        sprintf(txn->msg_shm, "MENSAGEM DO CONTAINER C%d\n", nf_id);
        //strcpy(txn->msg_shm,"MENSAGEM DO CONTAINER C2\n");
        txn->contador_containers = nf_id;
        
        bpf_map_lookup_elem(fd_mapa_sinal, &next_nf, &pid_alvo);
        data_send.sival_int = next_nf;
        sigqueue(pid_alvo, sigrtmin1, data_send);

    }

    return EXIT_SUCCESS;
}
