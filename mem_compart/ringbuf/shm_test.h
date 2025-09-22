#ifndef SHM_TEST
#define SHM_TEST

#include <stdio.h>
#include <stdint.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <stdarg.h>
struct sigshared_ringbuffer{
	uint64_t counter;
	uint64_t ringbuffer[(1U << 16)];
	uint64_t rb[(1U << 16)];

	uint64_t head;
	uint64_t tail;

    pid_t pids[10];

    void *sigshared_mem;
};

struct teste{
    char vetor_teste[100000];
    int nf_id;
};

#define N_ELEMENTOS (1U << 16)
#define RINGBUF_REGION "RINGBUF_MEM"
#define RINGBUF_TAM sizeof(struct sigshared_ringbuffer)

#define MEMPOOL_REGION "SIGSHARED_MEM"
#define MEMPOOL_TAM (1U << 16) * sizeof(struct teste)


/*********************************************************************/

void sigshared_print(const char *format, ...);

/*********************************************************************/
void *sigshared_create_mem();

/*********************************************************************/

void *sigshared_ptr_mem();

/*********************************************************************/

struct sigshared_ringbuffer *sigshared_mempool_create();

/*********************************************************************/

struct sigshared_ringbuffer *sigshared_mempool_ptr();

/*********************************************************************/

int sigshared_mempool_get(void *ptr);

/*********************************************************************/

int sigshared_mempool_put(uint64_t addr);

/*********************************************************************/

//struct teste *sigshared_mempool_access(uint64_t addr);
struct teste *sigshared_mempool_access(struct teste *temp, uint64_t addr);

/*********************************************************************/
#endif
