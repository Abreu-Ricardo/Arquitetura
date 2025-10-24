/*
# Copyright 2022 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

//#include <rte_branch_prediction.h>
//#include <rte_errno.h>
//#include <rte_mempool.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <sys/shm.h>

#include "sigshared.h"


#include "./include/io.h"
#include "./log/log.h"
#include "./include/spright.h"

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif /* SYS_pidfd_open */

#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif /* SYS_pidfd_getfd */

#define MAP_NAME "sock_map"

#define PORT_DUMMY 8081
#define PORT_SOCKMAP 8082

struct metadata
{
    int fn_id;
    void *obj;
};

static int sockfd_sk_msg = -1;

/* TODO: Cleanup on errors */
//static void *dummy_server(void *arg)
//{
//    struct sockaddr_in addr;
//    int sockfd_l;
//    int sockfd_c;
//    int optval;
//    int ret;
//
//    sockfd_l = socket(AF_INET, SOCK_STREAM, 0);
//    if (unlikely(sockfd_l == -1))
//    {
//        log_error("socket() error: %s", strerror(errno));
//        pthread_exit(NULL);
//    }
//
//    optval = 1;
//    ret = setsockopt(sockfd_l, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
//    if (unlikely(ret == -1))
//    {
//        log_error("setsockopt() error: %s", strerror(errno));
//        pthread_exit(NULL);
//    }
//
//    addr.sin_family = AF_INET;
//    addr.sin_port = htons(PORT_DUMMY);
//    addr.sin_addr.s_addr = htonl(INADDR_ANY);
//
//    ret = bind(sockfd_l, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
//    if (unlikely(ret == -1))
//    {
//        log_error("bind() error: %s", strerror(errno));
//        pthread_exit(NULL);
//    }
//
//    /* TODO: Correct backlog? */
//    // Provavelmente essas 10 conexoes sao os 10 servicos da online boutique
//    ret = listen(sockfd_l, 10);
//    if (unlikely(ret == -1))
//    {
//        log_error("listen() error: %s", strerror(errno));
//        pthread_exit(NULL);
//    }
//
//    while (1)
//    {
//        log_debug("Dummy server is ready for accepting new connection.");
//
//        sockfd_c = accept(sockfd_l, NULL, NULL);
//        if (unlikely(sockfd_c == -1))
//        {
//            log_error("accept() error: %s", strerror(errno));
//            pthread_exit(NULL);
//        }
//    }
//
//    pthread_exit(NULL);
//}

/* TODO: Cleanup on errors */
// Cria o servidor para ouvir os outros servicos da online boutique
// que vao mandar seus sockets e infos necessarios para se cadastrar
// no mapa eBPF
static int sockmap_server(int fd_sk_msg_map)
{
    struct sockaddr_in addr;
    ssize_t bytes_received;
    int sockfd_sk_msg_nf;
    int buffer[3];
    int sockfd_l;
    int sockfd_c;
    int optval;
    int pidfd;
    uint8_t i;
    int ret;

    sockfd_l = socket(AF_INET, SOCK_STREAM, 0);
    if (unlikely(sockfd_l == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }

    optval = 1;
    ret = setsockopt(sockfd_l, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
    if (unlikely(ret == -1))
    {
        log_error("setsockopt() error: %s", strerror(errno));
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_SOCKMAP);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = bind(sockfd_l, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (unlikely(ret == -1))
    {
        log_error("bind() error: %s", strerror(errno));
        return -1;
    }

    /* TODO: Correct backlog? */
    ret = listen(sockfd_l, 10);
    if (unlikely(ret == -1))
    {
        log_error("listen() error: %s", strerror(errno));
        return -1;
    }

    // TODO: change to while(1), so that sockmap server can keep registering
    // socket of newly created functions to sockmap
    for (i = 0; i < cfg->n_nfs; i++)
    {
        sockfd_c = accept(sockfd_l, NULL, NULL);
        if (unlikely(sockfd_c == -1))
        {
            log_error("accept() error: %s", strerror(errno));
            return -1;
        }

        bytes_received = recv(sockfd_c, buffer, 3 * sizeof(int), 0);
        if (unlikely(bytes_received == -1))
        {
            log_error("recv() error: %s", strerror(errno));
            return -1;
        }

        pidfd = syscall(SYS_pidfd_open, buffer[0], 0);
        if (unlikely(ret == -1))
        {
            log_error("SYS_pidfd_open() error: %s", strerror(errno));
            return -1;
        }

        sockfd_sk_msg_nf = syscall(SYS_pidfd_getfd, pidfd, buffer[1], 0);
        if (unlikely(ret == -1))
        {
            log_error("__NR_pidfd_getfd() error: %s", strerror(errno));
            return -1;
        }

        ret = bpf_map_update_elem(fd_sk_msg_map, &buffer[2], &sockfd_sk_msg_nf, 0);
        if (unlikely(ret < 0))
        {
            log_error("bpf_map_update_elem() error: %s", strerror(-ret));
            return -1;
        }

        log_info("%s: NF_ID %d -> SOCKFD %d", MAP_NAME, buffer[2], sockfd_sk_msg_nf);

        ret = close(sockfd_c);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }
    }

    ret = close(sockfd_l);
    if (unlikely(ret == -1))
    {
        log_error("close() error: %s", strerror(errno));
        return -1;
    }

    return 0;
}

struct sockmap_server_args
{
    int fd_sk_msg_map;
};

/*
 * We run the sockmap server as a separate thread, so that it can keep alive in the
 * background and register the socket of newly created functions to the eBPF
 * sockmap.
 */
void *sockmap_server_thread(void *arg)
{
    struct sockmap_server_args *args = (struct sockmap_server_args *)arg;
    int ret = sockmap_server(args->fd_sk_msg_map);
    if (unlikely(ret == -1))
    {
        log_error("sockmap_server() error");
    }
    return NULL;
}

/* TODO: Cleanup on errors */
static int sockmap_client(void)
{
    struct sockaddr_in addr;
    ssize_t bytes_sent;
    int buffer[3];
    int sockfd;
    int ret;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (unlikely(sockfd == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_SOCKMAP);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (unlikely(ret == -1))
    {
        log_error("connect() error: %s", strerror(errno));
        return -1;
    }

    buffer[0] = getpid();
    buffer[1] = sockfd_sk_msg;
    buffer[2] = fn_id;

    bytes_sent = send(sockfd, buffer, 3 * sizeof(int), 0);
    if (unlikely(bytes_sent == -1))
    {
        log_error("send() error: %s", strerror(errno));
        return -1;
    }

    ret = close(sockfd);
    if (unlikely(ret == -1))
    {
        log_error("close() error: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* TODO: Cleanup on errors */
static int init_gateway(void)
{
    //struct bpf_object *obj = NULL;
    struct sockaddr_in addr;
    
    //int fd_sk_msg_prog;
    //int fd_sk_msg_map;
    
    //pthread_t dummy_svr_thread;
    //pthread_t sockmap_svr_thread;
    int ret;

    // Acho que esse dummy_server eh soh lixo que eles estavam testando
    // Qual a utilidade desse server???
    //ret = pthread_create(&dummy_svr_thread, NULL, &dummy_server, NULL);
    //if (unlikely(ret != 0))
    //{
    //    log_error("pthread_create() error: %s", strerror(ret));
    //    return -1;
    //}

    //ret = bpf_prog_load("ebpf/sk_msg_kern.o", BPF_PROG_TYPE_SK_MSG, &obj, &fd_sk_msg_prog);
    //if (unlikely(ret < 0))
    //{
    //    log_error("bpf_prog_load() error: %s", strerror(-ret));
    //    return -1;
    //}

    //fd_sk_msg_map = bpf_object__find_map_fd_by_name(obj, MAP_NAME);
    //if (unlikely(fd_sk_msg_map < 0))
    //{
    //    log_error("bpf_object__find_map_fd_by_name() error: %s", strerror(-ret));
    //    return -1;
    //}

    //ret = bpf_prog_attach(fd_sk_msg_prog, fd_sk_msg_map, BPF_SK_MSG_VERDICT, 0);
    //if (unlikely(ret < 0))
    //{
    //    log_error("bpf_prog_attach() error: %s", strerror(-ret));
    //    return -1;
    //}

    //struct sockmap_server_args args = {.fd_sk_msg_map = fd_sk_msg_map};

    // --> Cria um servidor para "ouvir" as requisicoes dos servicos para salvar seus socket's FD
    //ret = pthread_create(&sockmap_svr_thread, NULL, sockmap_server_thread, &args);
    //if (unlikely(ret != 0))
    //{
    //    log_error("pthread_create() error: %s", strerror(ret));
    //    return -1;
    //}

    sockfd_sk_msg = socket(AF_INET, SOCK_STREAM, 0);
    if (unlikely(sockfd_sk_msg == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_DUMMY);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    ret = retry_connect(sockfd_sk_msg, (struct sockaddr *)&addr);
    if (unlikely(ret == -1))
    {
        log_error("connect() failed: %s", strerror(errno));
        return -1;
    }

    //ret = bpf_map_update_elem(fd_sk_msg_map, &fn_id, &sockfd_sk_msg, 0);
    //if (unlikely(ret < 0))
    //{
    //    log_error("bpf_map_update_elem() error: %s", strerror(-ret));
    //    return -1;
    //}

    return 0;
}

/* TODO: Cleanup on errors */
static int init_nf(void)
{
    struct sockaddr_in addr;
    int ret;

    sockfd_sk_msg = socket(AF_INET, SOCK_STREAM, 0);
    if (unlikely(sockfd_sk_msg == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT_DUMMY);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    ret = connect(sockfd_sk_msg, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
    if (unlikely(ret == -1))
    {
        log_error("connect() error: %s", strerror(errno));
        return -1;
    }

    // Cria o socket do cliente e manda para o sockmap_server()
    // assim eh possivel salvar o fd do socket do client pelo gateway.c
    ret = sockmap_client();
    if (unlikely(ret == -1))
    {
        log_error("sockmap_client() error");
        return -1;
    }

    return 0;
}

static int exit_gateway(void)
{
    return 0;
}

static int exit_nf(void)
{
    return 0;
}

// shm_mgr.c chama inicialmente essa funcao com valor de fn_id == -1
// gateway.c chama inicialmente essa funcao com valor de fn_id == 0, inicializa o gateway 
// frontend.c chama passando o id como argumento do processo e eh usado para atribuir o id da funcao
int io_init(void)
{
    int ret;

    // shm_mgr.c
    if (fn_id == -1)
    {
        return 0;
    }

    // gateway.c
    if (fn_id == 0)
    {
        ret = init_gateway();
        if (unlikely(ret == -1))
        {
            log_error("init_gateway() error");
            return -1;
        }
    }
    else
    {
        ret = init_nf();
        if (unlikely(ret == -1))
        {
            log_error("init_nf() error");
            return -1;
        }
    }

    return 0;
}

int io_exit(void)
{
    int ret;

    if (fn_id == -1)
    {
        return 0;
    }

    if (fn_id == 0)
    {
        ret = exit_gateway();
        if (unlikely(ret == -1))
        {
            log_error("exit_gateway() error");
            return -1;
        }
    }
    else
    {
        ret = exit_nf();
        if (unlikely(ret == -1))
        {
            log_error("exit_nf() error");
            return -1;
        }
    }

    return 0;
}


// Colocar o sigwaitinfo aqui!!!
//int io_rx(void **obj)
//{
//    ssize_t bytes_received;
//    struct metadata m;
//
//    bytes_received = recv(sockfd_sk_msg, &m, sizeof(struct metadata), 0);
//    if (unlikely(bytes_received == -1))
//    {
//        log_error("recv() error: %s", strerror(errno));
//        return -1;
//    }
//
//    *obj = m.obj;
//
//    return 0;
//}

//int io_rx(void **obj)
int io_rx(struct http_transaction *obj, void *sigshared_ptr)
{
    //ssize_t bytes_received;
    //struct metadata m;

    uint64_t addr;
    void *ptr = sigshared_ptr_mem();

    sigset_t set;
    siginfo_t data_rcv;
    //struct http_transaction *temp_txn = NULL;

    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGRTMIN+1); 
    //sigaddset(&set, SIGRTMIN+2);            
    sigprocmask(SIG_BLOCK, &set, NULL);

    
    printf("Esperando sinal...\n");
    if(sigwaitinfo(&set, &data_rcv) < 0){
        addr = (uint64_t)data_rcv.si_value.sival_ptr;
        
        ptr = /*(struct http_transaction *)*/ sigshared_ptr;
        ptr += (sizeof(struct http_transaction) * addr);
        //temp_txn = (struct http_transaction *)ptr;
        obj = (struct http_transaction *)ptr;

        return 0;
    }

    //return temp_txn;
    return -1;
}


// Enviar o sinal com dado aqui!!1
// sigqueue()
// TODO passar o addr do txn
//int io_tx(void *obj, uint8_t next_fn)
int io_tx(uint64_t addr, uint8_t next_fn)
{
    //ssize_t bytes_sent;
    //struct metadata m;
    
    sigval_t data_send;
    // ATENCAO --> SE FOR SOH UMA MAPA TABOM MAS SE NAO FOR MUDAR ISSO AQUI
    pid_t pid_alvo= sigshared_lookup_map( "onlineboutique_map", next_fn);
    int sigrtmin1 = SIGRTMIN+1;


    //m.fn_id = next_fn;
    //m.obj = obj;

    // Pegar o fd do mapa 
    //bpf_map_lookup_elem(fd_mapa_sinal, &key_map, &pid_alvo);
    data_send.sival_ptr = (void *)addr;

    if( sigqueue(pid_alvo, sigrtmin1, data_send) < 0){
        log_error("",strerror(errno));
    }

    //bytes_sent = send(sockfd_sk_msg, &m, sizeof(struct metadata), 0);
    //if (unlikely(bytes_sent == -1))
    //{
    //    log_error("send() error: %s", strerror(errno));
    //    return -1;
    //}

    return 0;
}
