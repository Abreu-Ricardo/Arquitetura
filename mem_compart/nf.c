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

    int ret_ftruncate = ftruncate(fd_sigshared_mem, tam_sigshared); 
    if ( ret_ftruncate == -1 ){
        perror("ERRO NO ftruncate()");
        exit(1);  
    }


    sigshared_ptr   = ( void *) mmap(0, tam_sigshared, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
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
    printf("PATH: %s\n", path);


    int pid = getpid();
    int key = atoi(argv[1]);
    bpf_map_update_elem(bpf_map__fd(skel->maps.mapa_sinal), &key, &pid, BPF_ANY);
    
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

    int next_nf = key;
    int pid_alvo;

    while(sigwaitinfo(&set, &data_rcv)){
        
        int addr = data_rcv.si_int;
        struct http_transaction *txn = (struct http_transaction *) sigshared_ptr;
        printf("MSG: %s\nContador: %d\n", txn->msg_shm, txn->contador_containers);

        strcpy(txn->msg_shm,"MENSAGEM DO CONTAINER C2\n");
        txn->contador_containers = key;
        
        bpf_map_lookup_elem(bpf_map__fd(skel->maps.mapa_sinal), &next_nf, &pid_alvo);
        data_send.sival_int = next_nf;
        sigqueue(pid_alvo, sigrtmin1, data_send);

    }

    return EXIT_SUCCESS;
}
