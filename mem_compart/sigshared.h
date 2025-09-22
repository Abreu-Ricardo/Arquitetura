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

#include <stddef.h>


#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xsk_kern.skel.h"
#include "http.h"

#define SIGSHARED_NAME "SIGSHARED_MEM"
#define SIGSHARED_MEMPOOL "SIGSHARED_MEMPOOL"
#define SIGSHARED_TAM (1U << 16) * sizeof(struct http_transaction)
#define N_ELEMENTOS (1U << 16) 

static void *sigshared_ptr;

struct sigshared_mempool{
    uint64_t cont;
    uint64_t index[N_ELEMENTOS];
};

extern struct sigshared_mempool *mempool;

/************************************************************************/
 void *sigshared_create_mem(int *fd_sigshared_mem, int tam_sigshared);

/************************************************************************/
 void *sigshared_ptr_mem(int *fd_sigshared_mem);


/************************************************************************/
/************************************************************************/
 int sigshared_update_map(char *map_name, int fn_id, int pid);


/************************************************************************/
 struct sigshared_mempool *sigshared_mempool_create(int *fd);


/************************************************************************/

 struct sigshared_mempool *sigshared_mempool_ptr(int *fd);


/************************************************************************/
struct http_transaction *sigshared_mempool_get(struct http_transaction *txn, int *fd_sigshared_mem);
  
/************************************************************************/
//static int sigshared_mempool_put(struct http_transaction *txn, int *fd_sigshared_mem , uint64_t addr){
 int sigshared_mempool_put(struct http_transaction *txn, int *fd_sigshared_mem);
 
/************************************************************************/
#endif 

