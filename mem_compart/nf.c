#include "sigshared.h"
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
        printf("Passe o id da nf: %s nf_id\n", argv[0]);
        return EXIT_FAILURE;
    } 

    char path[256]; 
    char temp[500]; 
    char *mapa_sinal_name = "mapa_sinal";
    char *dir_temp = getenv("SIGSHARED");
   
    sprintf(path,"%s/dados", dir_temp);
    sprintf(temp,"%s/%s", path, mapa_sinal_name);

    printf("TEMP: %s\n", temp);
    int fd_mapa_sinal =  bpf_obj_get(temp);
    if ( fd_mapa_sinal < 0){
        perror("Erro ao pegar FD do mapa");
        exit(1);
    }

    pid_t pid = getpid();
    uint32_t nf_id = atoi(argv[1]);
    printf("Atualizando mapa eBPF com pid: %d e com chave NF:%d\n", pid, nf_id);

    //if(sigshared_update_map(path, "mapa_sinal", nf_id, pid) < 0 ){
    if(sigshared_update_map("mapa_sinal", nf_id, pid) < 0 ){
        printf("sigshared_update_map retornou -1\n");
        return 1;
    } 

    sigshared_ptr = NULL;
    int fd_sigshared_mem;
    int tam_sigshared = sizeof(struct http_transaction) * 5;

    //cria_sigshared_mem(fd_sigshared_mem, tam_sigshared);
    sigshared_ptr = sigshared_ptr_mem(&fd_sigshared_mem);

    int sigrtmin1 = SIGRTMIN+1;
    
    siginfo_t data_rcv; 
    sigval_t data_send; 
    sigset_t set;
   
    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGRTMIN+1);            
    sigprocmask(SIG_BLOCK, &set, NULL); 

    int next_nf = nf_id+1;
    int pid_alvo;

    //imprime_mapa(fd_mapa_sinal, nf_id);

    struct http_transaction *txn;
    void *ptr;
    mempool = sigshared_mempool_ptr(&fd_sigshared_mem);

    printf("\n==NF%d== Esperando sinal...(PID %d)\n", nf_id, pid);
    while(sigwaitinfo(&set, &data_rcv) ){
     
        printf("PID de quem enviou o sinal: %d\n", data_rcv.si_pid );
        int addr = data_rcv.si_int;
        //struct http_transaction *txn = (struct http_transaction *) sigshared_ptr;

        //ptr = /*(struct http_transaction *)*/ sigshared_ptr;
        //ptr += (sizeof(struct http_transaction) * addr);
        //txn = (struct http_transaction *)ptr;
        
        txn = sigshared_mempool_get(txn, &fd_sigshared_mem);
        //txn = &txn[addr & N_ELEMENTOS];
        
        if(txn->contador_containers != 0){
            printf("==Erro posicao da memoria ja preenchida==\n");
            sigshared_mempool_put(txn, &fd_sigshared_mem);
        }

        sprintf(txn->msg_shm, "MENSAGEM DO CONTAINER C%d\n", nf_id);
        //sprintf(txn[nf_id].msg_shm, "MENSAGEM DO CONTAINER C%d\n", nf_id);
        //strcpy(txn->msg_shm,"MENSAGEM DO CONTAINER C2\n");
        txn->contador_containers = nf_id;
        //txn[nf_id].contador_containers = nf_id;

        printf("MSG: %s\nContador: %d\n", txn->msg_shm, txn->contador_containers);
        //printf("MSG: %s\nContador: %d\n", txn[nf_id].msg_shm, txn[nf_id].contador_containers);

        bpf_map_lookup_elem(fd_mapa_sinal, &next_nf, &pid_alvo);
        data_send.sival_int = next_nf;
        sigqueue(pid_alvo, sigrtmin1, data_send);

    }

    return EXIT_SUCCESS;
}
