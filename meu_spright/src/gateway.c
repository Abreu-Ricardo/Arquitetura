/*
# Copyright 2025 University of California, Riverside
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

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sched.h>

//#include <rte_branch_prediction.h>
//#include <rte_eal.h>
//#include <rte_errno.h>
//#include <rte_launch.h>
//#include <rte_lcore.h>
//#include <rte_mempool.h>
//#include <rte_memzone.h>

#include "sigshared.h"

#include "../../ebpf/xsk_kern.skel.h"

struct xsk_kern *skel;

int mapa_fd;
// 10 containers mais o gateway
int matriz[11][2] = {0};

sigset_t set;

#include "./include/http.h"
#include "./include/io.h"
#include "./include/spright.h"
#include "./include/timer.h"
#include "./include/utility.h"

#define IS_SERVER_TRUE 1
#define IS_SERVER_FALSE 0

#define HTTP_RESPONSE                                                                                                  \
    "HTTP/1.1 200 OK\r\n"                                                                                              \
    "Connection: close\r\n"                                                                                            \
    "Content-Type: text/plain\r\n"                                                                                     \
    "Content-Length: 13\r\n"                                                                                           \
    "\r\n"                                                                                                             \
    "Hello World\r\n"

struct server_vars
{
    int rpc_svr_sockfd; // Handle intra-cluster RPCs
    int ing_svr_sockfd; // Handle external clients
    int epfd;
};

typedef struct {
    int sockfd;
    int is_server;     // 1 for server_fd, 0 for client_fd
    int peer_svr_fd;   // Peer server_fd (for client_fd)
} sockfd_context_t;

int peer_node_sockfds[ROUTING_TABLE_SIZE];

static int dispatch_msg_to_fn(struct http_transaction *txn){
    //int ret;
    int pid = getpid();
    pid_t ret_io;

    if (txn->next_fn != sigshared_cfg->route[txn->route_id].hop[txn->hop_count])
    {
        if (txn->hop_count == 0)
        {
            txn->next_fn = sigshared_cfg->route[txn->route_id].hop[txn->hop_count];
            //log_debug("Dispatcher receives a request from conn_read.");
            //log_info("Dispatcher receives a request from conn_read.");
        }
        else
        {
            //log_debug("Dispatcher receives a request from conn_write or rpc_server.");
            log_info("Dispatcher receives a request from conn_write or rpc_server.");
        }
    }

    //ret = io_tx(&txn, txn->next_fn);
    //printf("ANTES DO IO_TX\n");
    
    //ret_io = io_tx(txn->addr, txn->next_fn, &mapa_fd);
    //ret_io = io_tx_matriz(txn->addr, txn->next_fn, &mapa_fd, matriz);
    ret_io = io_tx_matriz(txn->addr, txn->next_fn, &mapa_fd, pid, matriz, matriz[txn->next_fn][1]);
    
    //printf("DEPOIS DO IO_TX ret_io: %d\n", ret_io);
    
    if (unlikely(ret_io == -1)){
        log_error("io_tx() error");
        return -1;
    }

    return 0;
}

static int rpc_server_receive(int sockfd){
    int ret;
    uint64_t addr;
    struct http_transaction *txn = NULL;

    //ret = rte_mempool_get(cfg->mempool, (void **)&txn);
    //if (unlikely(ret < 0))
    //{
    //    log_error("rte_mempool_get() error: %s", rte_strerror(-ret));
    //    goto error_0;
    //}

    //printf("RPC_SERVER_RECEIVE()...\n");
    addr = sigshared_mempool_get(sigshared_ptr);
    
    //txn = sigshared_mempool_get(sigshared_ptr);
    txn = sigshared_mempool_access((void **)&txn, addr);
    if(txn == NULL){
        log_error("sigshared_mempool_get error: return NULL");
        goto error_0;
    }

    log_debug("Receiving message from remote gateway.");
    ssize_t total_bytes_received = read_full(sockfd, txn, sizeof(*txn));
    if (total_bytes_received == -1)
    {
        log_error("read_full() error");
        goto error_1;
    }
    else if (total_bytes_received != sizeof(*txn))
    {
        log_error("Incomplete transaction received: expected %ld, got %zd", sizeof(*txn), total_bytes_received);
        goto error_1;
    }

    log_debug("Bytes received: %zd. \t sizeof(*txn): %ld.", total_bytes_received, sizeof(*txn));

    // Send txn to local function
    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count,
                sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);

    ret = dispatch_msg_to_fn(txn);
    if (unlikely(ret == -1))
    {
        log_error("dispatch_msg_to_fn() error: %s", strerror(errno));
        goto error_1;
    }

    return 0;

error_1:
    //rte_mempool_put(cfg->mempool, txn);
    close(sockfd);
error_0:
    return -1;
}

static int rpc_client_setup(char *server_ip, uint16_t server_port, uint8_t peer_node_idx){
    log_info("RPC client connects with node %u (%s:%u).", peer_node_idx, cfg->nodes[peer_node_idx].ip_address,
             INTERNAL_SERVER_PORT);

    struct sockaddr_in server_addr;
    int sockfd;
    int ret;
    int opt = 1;

    log_debug("Destination Gateway Address (%s:%u).", server_ip, server_port);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (unlikely(sockfd == -1)){
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }

    // Set SO_REUSEADDR to reuse the address
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0){
        perror("setsockopt(SO_REUSEADDR) failed");
        close(sockfd);
        return -1;
    }

    configure_keepalive(sockfd);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    ret = retry_connect(sockfd, (struct sockaddr *)&server_addr);
    if (unlikely(ret == -1))
    {
        log_error("connect() failed: %s", strerror(errno));
        return -1;
    }

    return sockfd;
}

static int rpc_client_send(int peer_node_idx, struct http_transaction *txn)
{
    log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, \
        Caller Fn: %s (#%u), RPC Handler: %s()",
              txn->route_id, txn->hop_count, cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn,
              txn->caller_nf, txn->caller_fn, txn->rpc_handler);

    ssize_t bytes_sent;
    int sockfd = peer_node_sockfds[peer_node_idx];

    bytes_sent = send(sockfd, txn, sizeof(*txn), 0);

    log_debug("sockfd: %d, peer_node_idx: %d \t bytes_sent: %ld \t sizeof(*txn): %ld", sockfd, peer_node_idx, bytes_sent, sizeof(*txn));
    if (unlikely(bytes_sent == -1))
    {
        log_error("send() error: %s", strerror(errno));
        return -1;
    }

    log_debug("rpc_client_send is done.");

    return 0;
}

// static int rpc_client_close(int peer_node_idx) {
//
// 	int sockfd = peer_node_sockfds[peer_node_idx];
//
// 	int ret = close(sockfd);
// 	if (unlikely(ret == -1)) {
// 		log_error("close() error: %s", strerror(errno));
// 		return -1;
// 	}
//
// peer_node_sockfds[peer_node_idx] = 0;
//
// 	return 0;
// }

int rpc_client(struct http_transaction *txn)
{
    int ret;

    uint8_t peer_node_idx = get_node(txn->next_fn);

    if (peer_node_sockfds[peer_node_idx] == 0)
    {
        peer_node_sockfds[peer_node_idx] =
            rpc_client_setup(cfg->nodes[peer_node_idx].ip_address, INTERNAL_SERVER_PORT, peer_node_idx);
    }
    else if (peer_node_sockfds[peer_node_idx] < 0)
    {
        log_error("Invalid socket error.");
        return -1;
    }

    ret = rpc_client_send(peer_node_idx, txn);
    if (unlikely(ret == -1))
    {
        log_error("rpc_client_send() failed: %s", strerror(errno));
        return -1;
    }

   // rte_mempool_put(cfg->mempool, txn);

    return 0;
}

static int conn_accept(int svr_sockfd, struct server_vars *sv){
    struct epoll_event event;
    int clt_sockfd;
    int ret;

    clt_sockfd = accept(svr_sockfd, NULL, NULL);
    if (unlikely(clt_sockfd == -1)){
        log_error("accept() error: %s", strerror(errno));
        goto error_0;
    }

    sockfd_context_t *clt_sk_ctx = malloc(sizeof(sockfd_context_t));
    clt_sk_ctx->sockfd      = clt_sockfd;
    clt_sk_ctx->is_server   = IS_SERVER_FALSE;
    clt_sk_ctx->peer_svr_fd = svr_sockfd;

    /* Configure RPC connection keepalive 
     * TODO: keep external connection alive 
     */
    if (svr_sockfd == sv->rpc_svr_sockfd){
        log_debug("Set RPC connection to keep alive.");
        configure_keepalive(clt_sockfd);
        event.events = EPOLLIN;
    } else // svr_sockfd == sv->ing_svr_sockfd
    {
        event.events = EPOLLIN | EPOLLONESHOT;
    }

    event.data.ptr = clt_sk_ctx;

    ret = epoll_ctl(sv->epfd, EPOLL_CTL_ADD, clt_sockfd, &event);
    if (unlikely(ret == -1)){

        log_error("epoll_ctl() error: %s", strerror(errno));
        goto error_1;
    }

    return 0;

error_1:
    //close(clt_sockfd);
    //free(clt_sk_ctx);
error_0:
    return -1;
}

static int conn_close(struct server_vars *sv, int sockfd){
    int ret;
    int saved_errno = 0;

    if (sockfd < 0)
        return -1;

    // Try to remove from epoll; ENOENT means already removed.
    ret = epoll_ctl(sv->epfd, EPOLL_CTL_DEL, sockfd, NULL);
    if (ret == -1 && errno != ENOENT) {
        saved_errno = errno;
        log_error("epoll_ctl(DEL, fd=%d) error: %s", sockfd, strerror(errno));
    }

    // Always close the socket, even if epoll_ctl failed
    if (close(sockfd) == -1) {
        if (!saved_errno) saved_errno = errno;
        log_error("close(fd=%d) error: %s", sockfd, strerror(errno));
    }

    if (saved_errno) {
        errno = saved_errno;
        return -1;
    }

    return 0;
}


//static int conn_close(struct server_vars *sv, int sockfd){
//    int ret;
//
//    ret = epoll_ctl(sv->epfd, EPOLL_CTL_DEL, sockfd, NULL);
//    if (unlikely(ret == -1)){
//        log_error("epoll_ctl() error: %s", strerror(errno));
//        goto error_1;
//    }
//
//    ret = close(sockfd);
//    if (unlikely(ret == -1)){
//	    log_error("close() error: %s", strerror(errno));
//	    goto error_0;
//    }
//
//    return 0;
//
//error_1:
//    close(sockfd);
//error_0:
//    return -1;
//}

static void parse_route_id(struct http_transaction *txn){
    const char *string = strstr(txn->request, "/");
    //log_info("%s", string);

    // /1/cart
    if (unlikely(string == NULL)) {
        txn->route_id = 0;
	log_error("==gateway== txn->request EH NULO");
    } else {
        // Skip consecutive slashes in one step
        string += strspn(string, "/");
	
	//log_info("string: %s", string);
        
 	errno = 0;
        txn->route_id = strtol(string, NULL, 10);
        if (unlikely(errno != 0 || txn->route_id < 0)) {
            txn->route_id = 0;
	    log_error("==gateway== 2 route_id = 0");
        }
    }

    //log_debug("Route ID: %d", txn->route_id);
    //log_info("Route ID: %d", txn->route_id);
}

int cont=0;
// Recebe requisicao do usuario
static int conn_read(int sockfd, void* sk_ctx){

    struct http_transaction *txn = NULL;
    int ret;
    uint64_t addr;

    //ret = rte_mempool_get(cfg->mempool, (void **)&txn);
    //if (unlikely(ret < 0))
    //{
    //    log_error("rte_mempool_get() error: %s", rte_strerror(-ret));
    //    goto error_0;
    //}
    
    addr = sigshared_mempool_get(sigshared_ptr);
    //printf("RETORNOU do mempool_get() addr:%ld\n", addr);
    
    txn = sigshared_mempool_access((void **)&txn, addr);
    if ( txn == NULL){
        log_error("sigshared_mempool_get error: return NULL");
        goto error_0;
    }
	txn->addr = addr;
    //printf("==gateway(%d)== PASSOU DO mempool_get | txn->addr:%ld\n", getpid() , txn->addr);
    //log_info("==gateway(%d)== txn->addr:%ld\n", getpid(), txn->addr);


    /*********************************************************************************/
    // Recebe requisicao do usuario
    log_debug("Receiving from External User.");
    txn->length_request = read(sockfd, txn->request, HTTP_MSG_LENGTH_MAX);
    if (unlikely(txn->length_request == -1))
    {
        log_error("read() error: %s", strerror(errno));
        goto error_1;
    }


    txn->sockfd = sockfd;
    txn->sk_ctx = sk_ctx;

    //log_info("==gateway(%d)== Recebendo req do cliente%d addr:%ld(sock: %d)...\n", getpid() , cont++, txn->addr, txn->sockfd);

    // TODO: parse tenant ID from HTTP request,
    // use "0" as the default tenant ID for now.
    txn->tenant_id = 0;

    parse_route_id(txn);

    txn->hop_count = 0;

    //usleep(100);
    ret = dispatch_msg_to_fn(txn);
    if (unlikely(ret == -1)){
        log_error("dispatch_msg_to_fn() error: %s", strerror(errno));
        goto error_1;
    }

    return 0;

error_1:
    //rte_mempool_put(cfg->mempool, txn);
error_0:
    return -1;
}

//static int conn_write(int *sockfd){
static uint64_t conn_write(int *sockfd){
    struct http_transaction *txn = NULL;
    ssize_t bytes_sent;
    int ret;
    //int pid= getpid();
    
    uint64_t addr = -1;

    //log_debug("Waiting for the next TX event.");
    //log_info("Waiting for the next TX event.");
    //ret = io_rx((void **)&txn);

    //addr = io_rx(txn, sigshared_ptr, &set);
    //txn = io_rx(txn, sigshared_ptr, &set);
    io_rx((void **)&txn, sigshared_ptr, &set);
    //if (unlikely(addr == -1)){
    //    log_error("io_rx() error");
    //    return -1;
    //    //goto error_0;
    //}

    //txn = sigshared_mempool_access(txn, addr );
    if(txn == NULL){
    	log_error("==gateway== ERRO sigshared_mempool_access retornou NULL");
	return -1;
    }
    addr=txn->addr;

    //log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);
    //log_info("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);

    // Inter-node Communication (use rpc_client method)
    //if (sigshared_cfg->route[txn->route_id].hop[txn->hop_count] != fn_id)
    //{
    //    ret = rpc_client(txn);
    //    if (unlikely(ret == -1))
    //    {
    //        goto error_1;
    //    }

    //    return 1;
    //}

    txn->hop_count++;
    //log_debug("Next hop is Fn %u", sigshared_cfg->route[txn->route_id].hop[txn->hop_count]);
    //log_info("Next hop is Fn %u", sigshared_cfg->route[txn->route_id].hop[txn->hop_count]);
    txn->next_fn = sigshared_cfg->route[txn->route_id].hop[txn->hop_count];

    // Intra-node Communication (use io_tx() method)
    if (txn->hop_count < sigshared_cfg->route[txn->route_id].length){
        
	ret = dispatch_msg_to_fn(txn);
	if (unlikely(ret == -1)){
            log_error("dispatch_msg_to_fn() error: %s", strerror(errno));
	    return -1;
            //goto error_1;
        }

        return 1;
    }

    // Respond External Client
    *sockfd = txn->sockfd;

    txn->length_response = strlen(HTTP_RESPONSE);
    memcpy(txn->response, HTTP_RESPONSE, txn->length_response);

    //printf("==gateway== Enviando resposta ao cliente(sock: %d)...\n", *sockfd);
    //log_info("==gateway(%d)== Enviando resposta ao cliente addr:%ld(sock: %d)...\n", pid , txn->addr, *sockfd);

    //if (fcntl(*sockfd, F_GETFD) == -1) {
    //        log_error("Invalid socket fd=%d before write(): %s", *sockfd, strerror(errno));
    //        exit(1);
    //}

    bytes_sent = write(*sockfd, txn->response, txn->length_response);
    if (unlikely(bytes_sent == -1)){
	    log_error("write() error: %s", strerror(errno));
	    //exit(1);
	    return -1;
	    //goto error_1;
    }

    //free(txn->sk_ctx);
    //rte_mempool_put(cfg->mempool, txn);

    // Retornando o addr para liberar a regiao apos fechar a conexao com o cliente
    return addr;
    //return txn->addr;
    //return 0;

//error_1:
    //free(txn);
    //rte_mempool_put(cfg->mempool, txn);
//error_0:
    //return -1;
}

int req_client = 0;
static int event_process(struct epoll_event *event, struct server_vars *sv){
    int ret;

    log_debug("Processing an new RX event.");

    sockfd_context_t *sk_ctx = (sockfd_context_t *)event->data.ptr;

    log_debug("sk_ctx->sockfd: %d \t sv->rpc_svr_sockfd: %d", sk_ctx->sockfd, sv->rpc_svr_sockfd);

    if (sk_ctx->is_server){
        
	//log_debug("Accepting new connection on %s.", sk_ctx->sockfd == sv->rpc_svr_sockfd ? "RPC server" : "Ingress server");
	//log_info("Accepting new connection on %s.", sk_ctx->sockfd == sv->rpc_svr_sockfd ? "RPC server" : "Ingress server");
        ret = conn_accept(sk_ctx->sockfd, sv);
        
	if (unlikely(ret == -1)){
            log_error("conn_accept() error");
            return -1;
        }
    }
    else if(event->events & EPOLLIN){
        
	if (sk_ctx->peer_svr_fd == sv->ing_svr_sockfd){
            
	    //log_debug("Reading new data from external client.");
	    //log_info("Reading new data from external client---> %d.", req_client++);
            ret = conn_read(sk_ctx->sockfd, sk_ctx);
            
	    if (unlikely(ret == -1)){
                log_error("conn_read() error");
                return -1;
            }
        }
	//else if(sk_ctx->peer_svr_fd == sv->rpc_svr_sockfd){
        //    
        //    //log_debug("Reading new data from RPC client.");
        //    log_info("Reading new data from RPC client.");
        //    //ret = rpc_server_receive(sk_ctx->sockfd);
        //    //
	//    //if (unlikely(ret == -1)){
        //    //    log_error("rpc_server_receive() error");
        //    //    return -1;
        //    //}
        //} 
	else{
            log_error("Unknown peer_svr_fd");
            return -1;
        }

        if (ret == 1){
            
	    event->events |= EPOLLONESHOT;
            ret = epoll_ctl(sv->epfd, EPOLL_CTL_MOD, sk_ctx->sockfd, event);

            if (unlikely(ret == -1)){
                log_error("epoll_ctl() error: %s", strerror(errno));
                return -1;
            }
        }
    }
    else if (event->events & (EPOLLERR | EPOLLHUP)){

        /* TODO: Handle (EPOLLERR | EPOLLHUP) */
        log_error("(EPOLLERR | EPOLLHUP)");

        log_debug("Error - Close the connection.");
        
	ret = conn_close(sv, sk_ctx->sockfd);
        free(sk_ctx);
        if (unlikely(ret == -1)){
            log_error("conn_close() error");
            return -1;
        }
    }

    return 0;
}

/* TODO: Cleanup on errors */
static int server_init(struct server_vars *sv)
{
    int ret;

    log_info("Initializing intra-node I/O...");

    fn_id = 0;
    // Carregar o meu programa e os mapas, salvar o PID do gateway 

    // Cria um servidor para receber os dados para pegara o fd do socket da nf e salvar no mapa
    //ret = io_init();
    //if (unlikely(ret == -1))
    //{
    //    log_error("io_init() error");
    //    return -1;
    //}

    log_info("Initializing Ingress and RPC server sockets...");
    // Talvez tirar tudo? Ja que nao vai usar RPC e sim sinais?
    //sv->rpc_svr_sockfd = create_server_socket(cfg->nodes[cfg->local_node_idx].ip_address, INTERNAL_SERVER_PORT);
    sv->rpc_svr_sockfd = create_server_socket(sigshared_cfg->nodes[sigshared_cfg->local_node_idx].ip_address, INTERNAL_SERVER_PORT);
    if (unlikely(sv->rpc_svr_sockfd == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }
    sockfd_context_t *rpc_svr_sk_ctx = malloc(sizeof(sockfd_context_t));
    rpc_svr_sk_ctx->sockfd = sv->rpc_svr_sockfd;
    rpc_svr_sk_ctx->is_server = IS_SERVER_TRUE;
    rpc_svr_sk_ctx->peer_svr_fd = -1;

    //sv->ing_svr_sockfd = create_server_socket(sigshared_cfg->nodes[sigshared_cfg->local_node_idx].ip_address, EXTERNAL_SERVER_PORT);
    
    // INGRESS SOCKET AQUI, manter soh esse!!
    sv->ing_svr_sockfd = create_server_socket(sigshared_cfg->nodes[sigshared_cfg->local_node_idx].ip_address, EXTERNAL_SERVER_PORT);
    if (unlikely(sv->ing_svr_sockfd == -1))
    {
        log_error("socket() error: %s", strerror(errno));
        return -1;
    }
    sockfd_context_t *ing_svr_sk_ctx = malloc(sizeof(sockfd_context_t));
    ing_svr_sk_ctx->sockfd = sv->ing_svr_sockfd;
    ing_svr_sk_ctx->is_server = IS_SERVER_TRUE;
    ing_svr_sk_ctx->peer_svr_fd = -1;

    log_info("Initializing epoll...");
    sv->epfd = epoll_create1(0);
    if (unlikely(sv->epfd == -1))
    {
        log_error("epoll_create1() error: %s", strerror(errno));
        return -1;
    }

    struct epoll_event event;
    event.events = EPOLLIN;

    // epoll do socket rpc
    //event.data.ptr = rpc_svr_sk_ctx;
    //ret = epoll_ctl(sv->epfd, EPOLL_CTL_ADD, sv->rpc_svr_sockfd, &event);
    //if (unlikely(ret == -1))
    //{
    //    log_error("epoll_ctl() error: %s", strerror(errno));
    //    return -1;
    //}

    event.data.ptr = ing_svr_sk_ctx;
    ret = epoll_ctl(sv->epfd, EPOLL_CTL_ADD, sv->ing_svr_sockfd, &event);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        return -1;
    }

    return 0;
}

/* TODO: Cleanup on errors */
static int server_exit(struct server_vars *sv)
{
    int ret;

    //ret = epoll_ctl(sv->epfd, EPOLL_CTL_DEL, sv->rpc_svr_sockfd, NULL);
    //if (unlikely(ret == -1))
    //{
    //    log_error("epoll_ctl() error: %s", strerror(errno));
    //    return -1;
    //}

    ret = epoll_ctl(sv->epfd, EPOLL_CTL_DEL, sv->ing_svr_sockfd, NULL);
    if (unlikely(ret == -1))
    {
        log_error("epoll_ctl() error: %s", strerror(errno));
        return -1;
    }

    ret = close(sv->epfd);
    if (unlikely(ret == -1))
    {
        log_error("close() error: %s", strerror(errno));
        return -1;
    }

    //ret = close(sv->rpc_svr_sockfd);
    //if (unlikely(ret == -1))
    //{
    //    log_error("close() error: %s", strerror(errno));
    //    return -1;
    //}

    ret = close(sv->ing_svr_sockfd);
    if (unlikely(ret == -1))
    {
        log_error("close() error: %s", strerror(errno));
        return -1;
    }

    ret = io_exit();
    if (unlikely(ret == -1))
    {
        log_error("io_exit() error");
        return -1;
    }

    return 0;
}


// Recebe as requisicoes do cliente
//static int server_process_rx(void *arg)
static void server_process_rx(void *arg){

    struct epoll_event event[N_EVENTS_MAX];
    struct server_vars *sv = NULL;
    int n_fds;
    int ret;
    int i;

    sv = arg;

    while (1){
        
	log_debug("Waiting for new RX events...");
        n_fds = epoll_wait(sv->epfd, event, N_EVENTS_MAX, -1);
        
	if (unlikely(n_fds == -1)){
            log_error("epoll_wait() error: %s", strerror(errno));
	    printf("==gateway== ERRO epoll_wait retornou -1\n");
	    return;
            //return -1;
        }

        log_debug("epoll_wait() returns %d new events", n_fds);

        for (i = 0; i < n_fds; i++){
            
	    ret = event_process(&event[i], sv);
            if (unlikely(ret == -1)){
                
		log_error("event_process() error");
		printf("==gateway== ERRO event_process retornou -1\n");
		return;
                //return -1;
            }
        }
    }

    //return 0;
}

//static int server_process_tx(void *arg){
static void server_process_tx(void *arg){
    
    struct server_vars *sv = NULL;
    int sockfd;
    int ret;
    //int pid = getpid();
    uint64_t addr=-1;

    sv = arg;

    while (1){
        
	//ret = conn_write(&sockfd);
	addr = conn_write(&sockfd);
	//if (unlikely(ret == -1)){
	if (unlikely(addr == -1)){

            log_error("conn_write() error");
	    printf("==gateway== ERRO event_process retornou -1\n");
	    return;
            //return -1;
        }
        //else if (ret == 1){
        else if (addr == 1){
            continue;
        }

        //printf("==server_process_tx== antes do conn_close !!!\n");	
        
	//log_debug("Closing the connection after TX.\n");
	//log_info("==%d==Closing the connection after TX.\n", pid);
        //ret = conn_close(sv, sockfd);
	
        ret = conn_close(sv, sockfd);
	if (unlikely(ret == -1)){

            log_error("conn_close() error");
	    printf("==gateway== ERRO event_process retornou -1\n");
	    exit(1);
	    return;
            //return -1;
        }

	// Limpando txn[addr] dps da conexao ter sido fechada	
    	sigshared_mempool_put(addr);
    }
    
    return;
    //return 0;
}

static void metrics_collect(void){
    while (1){
        sleep(30);
    }
}

static int gateway(void)
{
    //const struct rte_memzone *memzone = NULL;
    //int NUM_LCORES = 4;
    //unsigned int lcore_worker[NUM_LCORES];
    struct server_vars sv;
    int ret;
    memset(peer_node_sockfds, 0, sizeof(peer_node_sockfds));


    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    fn_id = 0;
   
    char *temp = getenv("SIGSHARED");
    char path[300];
    sprintf(path, "%s/dados", temp);
    printf("###\n%s\n", path);

    skel = xsk_kern__open_and_load();
    if(skel == NULL){
	printf("+++ERROR+++\nskel == NULL\n");
    	return 0;
    }

    printf("==gateway==programa eBPF carregado...\n");
    //xsk_kern__attach(skel);
    // 10: ens1f1 --> eh a interface que tem 10.10.1.1 de IP
    skel->links.xdp_prog = bpf_program__attach_xdp( skel->progs.xdp_prog , 3 );
    if(skel->links.xdp_prog == NULL){
    	printf("==gateway== Erro ao acoplar programa XDP!!\n");
    	printf("==gateway== +++VERFICAR A INTERFACE PASSADA+++\n");
	return -1;
    }

    if( bpf_object__pin_maps(skel->obj, path) < 0){
	printf("==gateway== Erro ao pinar mapas!!\n");
    	return -1;
    }

    printf("==gateway== mapas eBPF pinado...\n");
    
    char *teste_path = "/mydata/spright/dados/mapa_sinal"; 
    int pid_gateway = getpid();
    //int fd_map = bpf_obj_get(path);
    int fd_map = bpf_obj_get(teste_path);
    if(fd_map < 0){
    	printf("==gateway== Erro ao pegar fd do mapa...\n");
	return -1;
    }
    //if( bpf_map_update_elem(fd_map, &fn_id, &pid_gateway, BPF_ANY) < 0  ){
    if( sigshared_update_map("mapa_sinal", fn_id, pid_gateway, &mapa_fd) < 0  ){
    	printf("Erro ao atualizar mapa\n");
	goto error_0;
    }

    printf("==(%d)gateway== mapa_sinal atualizado...\n", getpid());

    //memzone = rte_memzone_lookup(MEMZONE_NAME);
    //if (unlikely(memzone == NULL))
    //{
    //    log_error("rte_memzone_lookup() error");
    //    goto error_0;
    //}

    //cfg = memzone->addr;

    ret = server_init(&sv);
    if (unlikely(ret == -1))
    {
        log_error("server_init() error");
        goto error_0;
    }

    // Como adaptar isso??
    //for (int i = 0; i < NUM_LCORES; ++i) {
    //    lcore_worker[i] = (i == 0) 
    //        ? rte_get_next_lcore(rte_get_main_lcore(), 1, 1) 
    //        : rte_get_next_lcore(lcore_worker[i - 1], 1, 1);

    //    if (unlikely(lcore_worker[i] == RTE_MAX_LCORE)) {
    //        log_error("rte_get_next_lcore() error");
    //        goto error_1;
    //    }
    //}

    
    pthread_t rx_thread, tx_thread;
    cpu_set_t rx_cpuset, tx_cpuset;

    CPU_ZERO(&rx_cpuset);
    CPU_ZERO(&tx_cpuset);
    CPU_SET(1, &rx_cpuset);
    CPU_SET(2, &tx_cpuset);

    pthread_attr_t rx_attr, tx_attr;
    
    pthread_attr_init(&rx_attr);
    pthread_attr_init(&tx_attr);
    
    pthread_attr_setaffinity_np(&rx_attr, sizeof(cpu_set_t), &rx_cpuset);
    pthread_attr_setaffinity_np(&tx_attr, sizeof(cpu_set_t), &tx_cpuset);


    if( pthread_create(&rx_thread, &rx_attr, (void *)server_process_rx, (void *)&sv) < 0){
	    log_error("ERRO ao criar rx_thread");
            goto error_1;
   	
    }
    
    if( pthread_create(&tx_thread, &tx_attr, (void *)server_process_tx, (void *)&sv) < 0){
	    log_error("ERRO ao criar tx_thread");
            goto error_1;
    }
   	


    //int pid = fork();
    //if (pid == 0){
    //    int fpid = getpid();
    //    // libera o proc filho do pai
    //    if( setsid() < 0 )
    //        exit(-1);

    //    // atribuir o novo proc a uma CPU
    //    char settar_cpuf[50];
    //    sprintf(settar_cpuf, "taskset -cp 4 %d", fpid); 
    //    if (system(settar_cpuf) < 0){
    //        printf("Erro ao settar_cpu\n");
    //        exit(1);
    //    }

    //    server_process_rx(&sv);
    //}
    //else if (pid == -1){
    //    log_error("fork() error");
    //    goto error_1;
    //}

    //pid = fork();
    //if(pid == 0){
    //    int fpid = getpid();
    //    // libera o proc filho do pai
    //    if( setsid() < 0 )
    //        exit(-1);

    //    // atribuir o novo proc a uma CPU
    //    char settar_cpuf[50];
    //    sprintf(settar_cpuf, "taskset -cp 5 %d", fpid); 
    //    if (system(settar_cpuf) < 0){
    //        printf("Erro ao settar_cpu\n");
    //        exit(1);
    //    }

    //    server_process_tx(&sv);
    //}
    //else if (pid == -1){
    //    log_error("fork() error");
    //    goto error_1;
    //}
    

    // Atribui um core para a funcao server_process_rx
    //ret = rte_eal_remote_launch(server_process_rx, &sv, lcore_worker[0]);
    //if (unlikely(ret < 0))
    //{
    //    log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
    //    goto error_1;
    //}

    //// Atribui um core para a funcao server_process_tx
    //ret = rte_eal_remote_launch(server_process_tx, &sv, lcore_worker[1]);
    //if (unlikely(ret < 0))
    //{
    //    log_error("rte_eal_remote_launch() error: %s", rte_strerror(-ret));
    //    goto error_1;
    //}

    // Faz nada, acaba aqui o setup
    metrics_collect();

    //const char *error_messages[] = {
    //    "server_process_rx() error",
    //    "server_process_tx() error",
    //    "rpc_client() error",
    //    "rpc_server() error"
    //};

    //for (int i = 0; i < NUM_LCORES; i++) {
    //    ret = rte_eal_wait_lcore(lcore_worker[i]);
    //    if (unlikely(ret == -1)) {
    //        log_error("%s", error_messages[i]);
    //        goto error_1;
    //    }
    //}

    //ret = server_exit(&sv);
    //if (unlikely(ret == -1))
    //{
    //    log_error("server_exit() error");
    //    goto error_0;
    //}

    return 0;

error_1:
    server_exit(&sv);
error_0:
    return -1;
}

int main(int argc, char **argv)
{
    log_set_level_from_env();

    // show all logs larger than level DEBUG
    // The level enum is defined in log.h
    log_set_level(LOG_INFO);
    int ret;
    

    //char *sigshared_path;

    //// Option 2: Let getcwd allocate the buffer (more robust)
    //if ((sigshared_path = getcwd(NULL, 0)) == NULL) {
    //    perror("Erro ao pegar o diretorio");
    //} else {
    //    printf("Diretorio do SIGSHARED: %s\n", sigshared_path);
    //    //free(buffer); // Remember to free the allocated memory
    //}


    //if (setenv("SIGSHARED", sigshared_path, 0) == 0) {
    //    printf("Environment variable MY_VARIABLE attempted to be set without overwrite.\n");
    //} else {
    //    perror("Failed to set environment variable MY_VARIABLE without overwrite");
    //}


    sigshared_ptr = sigshared_ptr_mem();
    if(sigshared_ptr == NULL){
        log_error("ERRO NO sigshared_ptr");
        return 1;
    }

    sigshared_cfg = sigshared_cfg_ptr();
    if(sigshared_cfg == NULL){
        log_error("ERRO NO sigshared_cfg");
        return 1;
    }

    ringbuff = sigshared_mempool_ptr();
    if(ringbuff == NULL){
        log_error("ERRO NO ringbuff");
        return 1;
    }

    sigemptyset(&set);
    sigaddset(&set, SIGRTMIN+1);
    sigprocmask(SIG_BLOCK, &set, NULL);

    //ret = rte_eal_init(argc, argv);
    //if (unlikely(ret == -1))
    //{
    //    log_error("rte_eal_init() error: %s", rte_strerror(rte_errno));
    //    goto error_0;
    //}

    ret = gateway();
    if (unlikely(ret == -1))
    {
        log_error("gateway() error");
        goto error_1;
    }

    // Fim execucao --> Limpeza ja
    //ret = rte_eal_cleanup();
    //if (unlikely(ret < 0))
    //{
    //    log_error("rte_eal_cleanup() error: %s", rte_strerror(-ret));
    //    goto error_0;
    //}

    return 0;

error_1:
    printf("Erro ao inicializar o gateway\n");
    //rte_eal_cleanup();
//error_0:
//    return 1;
}
