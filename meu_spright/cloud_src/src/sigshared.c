#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>  
#include <sys/types.h> 
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <assert.h>
#include <stddef.h>

#include "sigshared.h"

#include "include/spright.h"
#include "include/http.h"


//#define INVALID_POSITION UINT64_MAX
//
//
//#ifndef unlikely
//#define unlikely(x) __builtin_expect(!!(x), 0)
//#endif
//
//#ifndef likely
//#define likely(x) __builtin_expect(!!(x), 1)
//#endif

//#include "xsk_kern.skel.h"

//#define SIGSHARED_NAME     "SIGSHARED_MEM"
//#define SIGSHARED_MEMPOOL  "SIGSHARED_MEMPOOL"
//#define SIGSHARED_TAM (1U << 16) * sizeof(struct http_transaction)
//#define N_POSICOES (1U << 16)


void *sigshared_ptr;
struct spright_cfg_s *sigshared_cfg;
int fd_sigshared_mem;
int fd_sigshared_mempool;
int fd_cfg_file;



struct sigshared_mempool *mempool;


/********************************************************************************************/
 void *sigshared_create_mem(){

    fd_sigshared_mem = shm_open(SIGSHARED_NAME, O_CREAT | O_RDWR, 0777);
    if (fd_sigshared_mem < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    int ret_ftruncate = ftruncate(fd_sigshared_mem, SIGSHARED_TAM); 
    if ( ret_ftruncate == -1 ){
        perror("ERRO NO ftruncate()");
        exit(1);  
    }

    //sigshared_ptr   = ( void *) mmap(0, tam_sigshared, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
    return ( void *) mmap(0, SIGSHARED_TAM, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
}

/********************************************************************************************/
// retorna ponteiro pro inicio da mem compart.
 void *sigshared_ptr_mem(){

    //*fd_sigshared_mem = shm_open(SIGSHARED_NAME, O_CREAT | O_RDWR, 0777);
    fd_sigshared_mem = shm_open(SIGSHARED_NAME, O_CREAT | O_RDWR, 0777);
    if ( fd_sigshared_mem < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    return ( void *) mmap(0, SIGSHARED_TAM, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
}

/********************************************************************************************/
// Cria a memoria do cfg e retorna o ponteiro para a struct spright_cfg_s *
 struct spright_cfg_s *sigshared_cfg_mem(){

    fd_cfg_file = shm_open("CFG_MEM", O_CREAT | O_RDWR, 0777);
    if (fd_cfg_file < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    int ret_ftruncate = ftruncate(fd_cfg_file, sizeof(struct spright_cfg_s)); 
    if ( ret_ftruncate == -1 ){
        perror("ERRO NO ftruncate()");
        exit(1);  
    }

    //sigshared_ptr   = ( void *) mmap(0, tam_sigshared, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
    return ( struct spright_cfg_s *) mmap(0, sizeof(struct spright_cfg_s), PROT_WRITE, MAP_SHARED, fd_cfg_file, 0);
}

/********************************************************************************************/
// retorna o ponteiro para a memoria da regiao de configuracao
 struct spright_cfg_s *sigshared_cfg_ptr(){

    fd_cfg_file = shm_open("CFG_MEM", O_CREAT | O_RDWR, 0777);
    if (fd_cfg_file < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }


    //sigshared_ptr   = ( void *) mmap(0, tam_sigshared, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);
    return ( struct spright_cfg_s *) mmap(0, sizeof(struct spright_cfg_s), PROT_WRITE, MAP_SHARED, fd_cfg_file, 0);
}

/********************************************************************************************/
// Atualiza o mapa eBPF com nome do mapa e valor a serem utilizados para salvar
 int sigshared_update_map(char *map_name, int fn_id, int pid){

    char temp[256];
    char *dir_temp = getenv("SIGSHARED");
    int map_fd;

    sprintf(temp, "%s/dados/%s", dir_temp, map_name);
    map_fd = bpf_obj_get(temp);

    if(bpf_map_update_elem(map_fd, &fn_id, &pid, BPF_ANY) < 0){
        perror("Erro ao atualizar o mapa eBPF");
        return -1;
    }

    return 0;
}

/********************************************************************************************/
// Retorna o pid, passe o nome do mapa e a chave
 pid_t sigshared_lookup_map(char *map_name, int key){

    char temp[256];
    char *dir_temp = getenv("SIGSHARED");
    int map_fd;
    pid_t pid_ret;

    sprintf(temp, "%s/dados/%s", dir_temp, map_name);
    map_fd = bpf_obj_get(temp);

    if( bpf_map_lookup_elem(map_fd, &key, &pid_ret) < 0 ){
        perror("Erro ao atualizar o mapa eBPF");
        return -1;
    }

    return pid_ret;
}


/********************************************************************************************/
/********************************************************************************************/
 struct sigshared_mempool *sigshared_mempool_create(int *fd){
    *fd = shm_open(SIGSHARED_MEMPOOL, O_CREAT | O_RDWR, 0777);
    if (*fd < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    int ret_ftruncate = ftruncate(*fd, sizeof(struct sigshared_mempool)); 
    if ( ret_ftruncate == -1 ){
        perror("ERRO NO ftruncate()");
        exit(1);  
    }

    struct sigshared_mempool *aux = ( struct sigshared_mempool *) mmap(0, sizeof(struct sigshared_mempool), PROT_WRITE, MAP_SHARED, *fd, 0);
    for(int i=0; i< N_POSICOES; i++){
        aux->index[i] = i;
    }

    return ( struct sigshared_mempool *) mmap(0, sizeof(struct sigshared_mempool), PROT_WRITE, MAP_SHARED, *fd, 0);
}

/********************************************************************************************/

 struct sigshared_mempool *sigshared_mempool_ptr(int *fd){
    int fd_aux = shm_open(SIGSHARED_MEMPOOL, O_CREAT | O_RDWR, 0777);
    if (*fd < 0){ 
        perror("ERRO NO shm_open()");
        exit(1);
    }

    *fd = fd_aux;
    return ( struct sigshared_mempool *) mmap(0, sizeof(struct sigshared_mempool), PROT_WRITE, MAP_SHARED, fd_aux, 0);
}

/********************************************************************************************/
 struct http_transaction *sigshared_mempool_get(struct http_transaction *txn, int *fd_sigshared_mem){
  
    while ( mempool->lock == 0){
        mempool->lock = 1;

        if( mempool->cont == N_POSICOES){
            printf("SEM ESPACO NO BUFFER\n");
            return NULL;
        }

        txn = (struct http_transaction *) sigshared_ptr_mem(); 
        uint64_t temp_cont = __atomic_load_n(&mempool->cont , __ATOMIC_RELAXED); 

        printf("Valor do temp_cont:%ld \n", temp_cont);

        //mempool->cont++;
        txn = &txn[temp_cont];
        txn->addr = temp_cont;
        __atomic_store_n(&mempool->cont, mempool->cont+1, __ATOMIC_RELEASE);

        mempool->lock = 0;
    }
    return txn;
}

/********************************************************************************************/
//static int sigshared_mempool_put(struct http_transaction *txn, int *fd_sigshared_mem , uint64_t addr){
int sigshared_mempool_put(struct http_transaction *txn, int *fd_sigshared_mem){
  
    while (mempool->lock == 0){
        mempool->lock = 1;
        
        if(mempool->cont <= 0 ){
            printf("Erro, contador com valor negativo\n");
            return -1;
        }

        //uint64_t temp_cont = __atomic_load_n(&mempool->index[mempool->cont] , __ATOMIC_RELAXED); 
        memset( txn, 0, sizeof(struct http_transaction));

        //mempool->cont--;
        __atomic_store_n(&mempool->cont, mempool->cont-1, __ATOMIC_RELEASE);
        
        mempool->lock = 0;
    }

    return 0;
}

/********************************************************************************************/

