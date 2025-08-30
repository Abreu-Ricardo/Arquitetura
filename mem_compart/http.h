#ifndef HTTP_H
#define HTTP_H

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



#include "xsk_kern.skel.h"

#define SIGSHARED_NAME "SIGSHARED_MEM"

static void *sigshared_ptr;

struct http_transaction{
    int contador_containers;
    char msg_shm[255];
};

#endif 

