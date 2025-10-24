#ifndef SIGSHARED_H
#define SIGSHARED_H

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

#include "include/spright.h"
#include "include/http.h"


#define INVALID_POSITION UINT64_MAX


#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

//#include "xsk_kern.skel.h"

#define SIGSHARED_NAME     "SIGSHARED_MEM"
#define SIGSHARED_MEMPOOL  "SIGSHARED_MEMPOOL"
#define SIGSHARED_TAM (1U << 16) * sizeof(struct http_transaction)
#define N_POSICOES (1U << 16)

extern void *sigshared_ptr;
extern struct spright_cfg_s *sigshared_cfg;

extern int fd_sigshared_mem;
extern int fd_sigshared_mempool;
extern int fd_cfg_file;

struct sigshared_mempool{
    int lock;
	uint64_t mempool_ptr;
    uint64_t cont;
	uint64_t index[N_POSICOES];
};

extern struct sigshared_mempool *mempool;


/********************************************************************************************/
void *sigshared_create_mem();


/********************************************************************************************/
// retorna ponteiro pro inicio da mem compart.
 void *sigshared_ptr_mem();



/********************************************************************************************/
// Cria a memoria do cfg e retorna o ponteiro para a struct spright_cfg_s *
struct spright_cfg_s *sigshared_cfg_mem();


/********************************************************************************************/
// retorna o ponteiro para a memoria da regiao de configuracao
struct spright_cfg_s *sigshared_cfg_ptr();
 

/********************************************************************************************/
// Atualiza o mapa eBPF com nome do mapa e valor a serem utilizados para salvar
int sigshared_update_map(char *map_name, int fn_id, int pid);
/********************************************************************************************/
// Retorna o pid, passe o nome do mapa e a chave
 pid_t sigshared_lookup_map(char *map_name, int key);
/********************************************************************************************/
/********************************************************************************************/
 struct sigshared_mempool *sigshared_mempool_create(int *fd);


/********************************************************************************************/

 struct sigshared_mempool *sigshared_mempool_ptr(int *fd);

/********************************************************************************************/
 struct http_transaction *sigshared_mempool_get(struct http_transaction *txn, int *fd_sigshared_mem);
/********************************************************************************************/
//static int sigshared_mempool_put(struct http_transaction *txn, int *fd_sigshared_mem , uint64_t addr){
 int sigshared_mempool_put(struct http_transaction *txn, int *fd_sigshared_mem);


/********************************************************************************************/



#endif 

