#include "sigshared.h"
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include "http.h"

struct xsk_kern_bpf *skel = NULL;
char path[256]; 
char aux[300];


void clean_bpf(int signum){

    printf("\nRemovendo o programa eBPF...\n");
    
    shm_unlink(SIGSHARED_NAME);
    shm_unlink(SIGSHARED_MEMPOOL);
    
    sprintf(aux, "%s/mapa_sinal", path);
    int map_fd = bpf_obj_get(aux);
    printf("aux: %s\nmap_fd: %d\n", aux, map_fd);

    int pid, key=0;
    for(int i = 0; i< 3; i++){
        key = i+1;
        if(bpf_map_lookup_elem(map_fd, &key, &pid) < 0){
            printf("==Erro ao consultar o mapa_sinal: key: %d==\n", key);
        }
        printf("Enviado sinal SIGKILL para o PID %d...\n", pid);
        kill( pid, SIGKILL);
    }

    bpf_object__unpin_maps(skel->obj, path);
    xsk_kern_bpf__detach(skel);
    xsk_kern_bpf__destroy(skel);

    exit(0);
}
/***********************************/
void map_bpf(){
    
    printf("map_bpf\n");

}

/***********************************/

void imprime_mapa(int fd_mapa_sinal, int nf_id){

    pid_t temp;

    //for(uint32_t i=0; i <= nf_id; i++){

    //    if ( bpf_map_lookup_elem(fd_mapa_sinal, &i, &temp) < 0 ){ 
    //        perror("Erro ao consultar o mapa eBPF"); 
    //        continue; 
    //    }

    //    printf("mapa_sinal[%d]: %d\n", /*nf_id*/i, temp);
    //}

    int ret = 0;
    do{
        printf("Digite a posicao a verificar no mapa(-1 para sair) \n");
        scanf("%d", &ret);
    
        if ( ret != -1 && bpf_map_lookup_elem(fd_mapa_sinal, &ret, &temp) < 0 ){ 
            perror("Erro ao consultar o mapa eBPF"); 
            continue; 
        }

        printf("mapa_sinal[%d]: %d\n", /*nf_id*/ret, temp);
    }while(ret != -1);

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
    signal(SIGUSR1, map_bpf);

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
    //bpf_map_update_elem(bpf_map__fd(skel->maps.mapa_sinal), &key, &pid, BPF_ANY);

    int gateway_id = 0;
    //if(sigshared_update_map(path, "mapa_sinal", gateway_id, pid) < 0 ){
    if(sigshared_update_map("mapa_sinal", gateway_id, pid) < 0 ){
        printf("Erro do sigshared_update_map()\n");
        return -1;
    }
    
    sigshared_ptr = NULL;
    int fd_sigshared_mem;
    //int tam_sigshared = sizeof(struct http_transaction) * 5;
    int tam_sigshared = (1U << 16) * sizeof(struct http_transaction);
    printf("tamanho da regiao alocada: %d\n", tam_sigshared);

    //cria_sigshared_mem(fd_sigshared_mem, tam_sigshared);
    sigshared_ptr = sigshared_create_mem(&fd_sigshared_mem, tam_sigshared);
    if(sigshared_ptr == NULL){
        printf("Erro ao criar mem...\n");
        clean_bpf(SIGINT);
    }

    int mempool_fd;
    mempool = sigshared_mempool_create(&mempool_fd);
    if(mempool == NULL){
        printf("Erro ao criar mem...\n");
        clean_bpf(SIGINT);
    }
    //mempool->cont++;

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
    while( sigwait(&set, &sigrtmin1) == 0 ){
        //if( sigwait(&set, &sigrtmin1) == 0 ){

        printf("--> Recebeu sinal\n");
        // fazer consulta no mapa ebpf para pegar o PID
        bpf_map_lookup_elem(bpf_map__fd(skel->maps.mapa_sinal), &next_nf, &pid_alvo);
        data_send.sival_int = next_nf;

        if(sigqueue(pid_alvo, SIGRTMIN+1, data_send) < 0){
            perror("Erro ao enviar sinal");
        }
        sleep(3);

        //}

        struct http_transaction *txn;
        txn = (struct http_transaction *) sigshared_ptr;



        for(int i=0; i< 10; i++){

            printf("contador[%d]: %d\n", i, txn[i].contador_containers );
            printf("Mensagem[%d]: %s\n", i, txn[i].msg_shm );
            printf("\n\n");

        }

        /*********************************************************************/
        sigshared_mempool_put(&txn[0] , &fd_sigshared_mem);
        sigshared_mempool_put(&txn[1] , &fd_sigshared_mem);
        sigshared_mempool_put(&txn[2] , &fd_sigshared_mem);

        for(int i=0; i< 10; i++){

            printf("contador[%d]: %d\n", i, txn[i].contador_containers );
            printf("Mensagem[%d]: %s\n", i, txn[i].msg_shm );
            printf("\n\n");

        }

        printf("VALOR do cont: %ld | index[cont] = %ld\n", mempool->cont, mempool->index[mempool->cont]);

    }


    clean_bpf(SIGINT);
    return EXIT_SUCCESS;
}
