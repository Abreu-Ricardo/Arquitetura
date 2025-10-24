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

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <time.h>
#include <unistd.h>

//#include <rte_branch_prediction.h>
//#include <rte_eal.h>
//#include <rte_errno.h>
//#include <rte_memzone.h>

#include <execinfo.h>
#include "../sigshared.h"

int mapa_fd;
int matriz[11][2] = {0};
sigset_t set;


#include "../include/http.h"
#include "../include/io.h"
#include "../include/shm_rpc.h"
#include "../include/spright.h"
#include "../include/utility.h"

static int pipefd_rx[UINT8_MAX][2];
static int pipefd_tx[UINT8_MAX][2];

// char defaultCurrency[5] = "CAD";

static void setCurrencyHandler(struct http_transaction *txn){

    log_debug("Call setCurrencyHandler");
    //log_info("Call setCurrencyHandler");
    //char *query = httpQueryParser(txn->request);
    
    //char query[HTTP_MSG_LENGTH_MAX];
    //httpQueryParser(txn->request, query);
    char aux[HTTP_MSG_LENGTH_MAX];
    //char *query = httpQueryParser(txn->request, aux);
    char *query = httpQueryParser(txn->request, aux, HTTP_MSG_LENGTH_MAX);
    if (!query) {
	    log_error("Invalid query string");
	    exit(1);
	    //return;
    }


    //log_info("QUERY: %s", query);

    char _defaultCurrency[5] = "CAD";
    //strcpy(_defaultCurrency, strchr(query, '=') + 1);
    
    // EH AQUI OOHH O ERRO  TODO
    char *quantidade = strchr(query, '=') + 1; 
    //log_info("qtd: %s", quantidade );
    strncpy(_defaultCurrency, quantidade, sizeof(*quantidade));

    txn->hop_count += 100;
    txn->next_fn = GATEWAY; // Hack: force gateway to return a response
    
    //free(query);

}

static void homeHandler(struct http_transaction *txn){

    log_debug("Call homeHandler ### Hop: %u", txn->hop_count);

    if (txn->hop_count == 0){
        // next_fn = currency.c
        getCurrencies(txn);
    }
    else if (txn->hop_count == 1){
        // next_fn = productcatalog.c
        getProducts(txn);
        txn->productViewCntr = 0;
    }
    else if (txn->hop_count == 2){
        // next_fn = cart.c
        getCart(txn);
    }
    else if (txn->hop_count == 3){
        // next_fn = currency.c
        convertCurrencyOfProducts(txn);
        homeHandler(txn);
    }
    else if (txn->hop_count == 4){
        // next_fn = ad.c
        chooseAd(txn);
    }
    else if (txn->hop_count == 5){
        // next_fn = gateway.c
        returnResponse(txn);
    }
    else{
        // next_fn = gateway.c
        log_warn("homeHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
    return;
}

static void productHandler(struct http_transaction *txn)
{
    log_debug("Call productHandler ### Hop: %u", txn->hop_count);

    if (txn->hop_count == 0)
    {
        // next_fn = productcatalog.c
        getProduct(txn);
        txn->productViewCntr = 0;
    }
    else if (txn->hop_count == 1)
    {
        // next_fn = currency.c
        getCurrencies(txn);
    }
    else if (txn->hop_count == 2)
    {
        // next_fn = cart.c
        getCart(txn);
    }
    else if (txn->hop_count == 3)
    {
        // next_fn = recommendations.c
        // next_fn = currency.c
        convertCurrencyOfProduct(txn);
    }
    else if (txn->hop_count == 4)
    {
        // next_fn = ad.c
        chooseAd(txn);
    }
    else if (txn->hop_count == 5)
    {
        // next_fn = gateway.c
        returnResponse(txn);
    }
    else
    {
        // next_fn = gateway.c
        log_warn("productHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
    return;
}

static void addToCartHandler(struct http_transaction *txn)
{
    log_debug("Call addToCartHandler ### Hop: %u", txn->hop_count);
    if (txn->hop_count == 0)
    {
        // next_fn = productcatalog.c
        getProduct(txn);
        txn->productViewCntr = 0;
    }
    else if (txn->hop_count == 1)
    {
        // next_fn = cart.c
        insertCart(txn);
    }
    else if (txn->hop_count == 2)
    {
        // next_fn = gateway.c
        returnResponse(txn);
    }
    else
    {
        // next_fn = gateway.c
        log_debug("addToCartHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
}

static void viewCartHandler(struct http_transaction *txn)
{
    log_debug("Call viewCartHandler ### Hop: %u", txn->hop_count);
    if (txn->hop_count == 0)
    {
        // next_fn = currency.c
        getCurrencies(txn);
    }
    else if (txn->hop_count == 1)
    {
        // next_fn = cart.c
        getCart(txn);
        txn->cartItemViewCntr = 0;
        strcpy(txn->total_price.CurrencyCode, defaultCurrency);
    }
    else if (txn->hop_count == 2)
    {
        // next_fn = recommendations.c 
        getRecommendations(txn);
    }
    else if (txn->hop_count == 3)
    {
        // next_fn = shipping.c 
        getShippingQuote(txn);
    }
    else if (txn->hop_count == 4)
    {
        // next_fn = currency.c 
        convertCurrencyOfShippingQuote(txn);
        if (txn->get_quote_response.conversion_flag == true)
        {
            // next_fn = productcatalog.c
            getCartItemInfo(txn);
            txn->hop_count++;
        }
        else
        {
            log_debug("Set get_quote_response.conversion_flag as true");
            txn->get_quote_response.conversion_flag = true;
        }
    }
    else if (txn->hop_count == 5)
    {
        // next_fn = productcatalog.c
        getCartItemInfo(txn);
    }
    else if (txn->hop_count == 6)
    {
        // next_fn = currency.c 
        convertCurrencyOfCart(txn);
    }
    else
    {
        // next_fn = gateway.c
        log_debug("viewCartHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
}

static void PlaceOrder(struct http_transaction *txn)
{
    parsePlaceOrderRequest(txn);
    // PrintPlaceOrderRequest(txn);

    strcpy(txn->rpc_handler, "PlaceOrder");
   
    if(txn->caller_fn != FRONTEND) 
    	txn->caller_fn = FRONTEND;
    if(txn->next_fn != CHECKOUT_SVC)
    	txn->next_fn = CHECKOUT_SVC;

    //log_info("caller_fn:%d | next_fn:%d", txn->caller_nf, txn->next_fn);
    
    txn->hop_count++;
    txn->checkoutsvc_hop_cnt = 0;

}

static void placeOrderHandler(struct http_transaction *txn)
{
    log_debug("Call placeOrderHandler ### Hop: %u", txn->hop_count);

    if (txn->hop_count == 0)
    {
        // next_fn = checkout.c
        PlaceOrder(txn);
    }
    else if (txn->hop_count == 1)
    {
        // next_fn = recommendations.c
        getRecommendations(txn);
    }
    else if (txn->hop_count == 2)
    {
        // next_fn = currency.c
        getCurrencies(txn);
    }
    else if (txn->hop_count == 3)
    {
        // next_fn = gateway.c 
        returnResponse(txn);
    }
    else
    {
        log_debug("placeOrderHandler doesn't know what to do for HOP %u.", txn->hop_count);
        returnResponse(txn);
    }
}

static void httpRequestDispatcher(struct http_transaction *txn)
{

    char *req = txn->request;
    // log_debug("Receive one msg: %s", req);
    
    // Requisicao de checkout
    if (strstr(req, "/1/cart/checkout") != NULL)
    {
        // next_fn = checkout.c
        // next_fn = recommendations.c
        // next_fn = currency.c
        // next_fn = gateway.c
        placeOrderHandler(txn);
    }
    else if (strstr(req, "/1/cart") != NULL)
    {
        if (strstr(req, "GET"))
        {
            // next_fn = currency.c 
            // next_fn = cart.c
            // next_fn = recommendations.c
            // next_fn = shipping.c
            // next_fn = productcatalog.c
            viewCartHandler(txn);
        }
        else if (strstr(req, "POST"))
        {
            // next_fn = productcatalag.c 
            // next_fn = cart.c
            // next_fn = gateway.c
            addToCartHandler(txn);
        }
        else
        {
            log_debug("No handler found in frontend: %s", req);
        }
    }
    else if (strstr(req, "/1/product") != NULL)
    {
        // next_fn = productcatalog.c
        // next_fn = currency.c
        // next_fn = cart.c
        // next_fn = recommendations.c
        // next_fn = ad.c
        // next_fn = gateway.c
        productHandler(txn);
    }
    else if (strstr(req, "/1/setCurrency") != NULL)
    {
        // next_fn = gateway.c 
        setCurrencyHandler(txn);
    }
    else if (strstr(req, "/1") != NULL)
    {
        // next_fn = currency.c 
        // next_fn = productcatalog.c
        // next_fn = ad.c
        // next_fn = cart.c
        // next_fn = gateway.c
        homeHandler(txn);
    }
    else
    {
        log_debug("Unknown handler. Check your HTTP Query, human!: %s", req);
        returnResponse(txn);
    }

    return;
}

static void *nf_worker(void *arg){
    //struct http_transaction *txn = NULL;
    struct http_transaction *txn;
    ssize_t bytes_written;
    ssize_t bytes_read;
    uint8_t index;

    /* TODO: Careful with this pointer as it may point to a stack */
    index = (uint64_t)arg;

    while (1){

        bytes_read = read(pipefd_rx[index][0], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_read == -1)){
            log_error("read() error: %s", strerror(errno));
            return NULL;
        }
        // log_debug("Receive one msg: %s", txn->request);
        //log_info("Receive one msg: %s", txn->request);
        // Trata a requisicao e escreve as informacoes para o proximo container
        httpRequestDispatcher(txn);

        bytes_written = write(pipefd_tx[index][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1)){
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }
    }

    return NULL;
}

static void *nf_rx(void *arg){
    //struct http_transaction *txn = NULL;
    struct http_transaction *txn;
    ssize_t bytes_written;
    uint8_t i;
    //int ret;
    //uint64_t addr;
    //int pid = getpid();

    //txn = (struct http_transaction *) mmap(0, SIGSHARED_TAM, PROT_WRITE, MAP_SHARED, fd_sigshared_mem, 0);


    for (i = 0;; i = (i + 1) % sigshared_cfg->nf[fn_id - 1].n_threads){

	//log_info("Recebendo sinal...");
        //ret = io_rx((void **)&txn);
        //addr = io_rx(txn, sigshared_ptr, &set);
        //txn = io_rx(txn, sigshared_ptr, &set);
        io_rx((void **)&txn, sigshared_ptr, &set);
        //if (unlikely(ret == -1))
        //if (unlikely(addr == -1)){
        //    log_error("io_rx() error");
        //    return NULL;
        //}
	
	//txn = sigshared_mempool_access(txn, addr);
	if(unlikely(txn == NULL)){
		printf("==frontend== txn retornou NULL\n");
		exit(1);
	}

	//printf("==frontend== dps sigshared_mempool_access() | txn->addr:%ld\n", txn->addr);

        bytes_written = write(pipefd_rx[i][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1)){
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }

	//log_info("%s", txn->request);	
	//log_info("==front%d== txn->addr:%ld\n", pid, txn->addr);
        //log_info("(ADDR RX:%ld), Route id: %u, Next Fn: %u, Caller Fn: %s (#%u) ", txn->addr, txn->route_id, txn->next_fn, txn->caller_nf, txn->caller_fn);

    }

    return NULL;
}

static void *nf_tx(void *arg)
{
    struct epoll_event event[UINT8_MAX]; /* TODO: Use Macro */
    //struct http_transaction *txn = NULL;
    struct http_transaction *txn;
    ssize_t bytes_read;
    uint8_t i;
    int n_fds;
    int epfd;
    int ret;
    int ret_io;
    int pid = getpid();

    epfd = epoll_create1(0);
    if (unlikely(epfd == -1))
    {
        log_error("epoll_create1() error: %s", strerror(errno));
        return NULL;
    }

    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = set_nonblocking(pipefd_tx[i][0]);
        if (unlikely(ret == -1))
        {
            return NULL;
        }

        event[0].events = EPOLLIN;
        event[0].data.fd = pipefd_tx[i][0];

        ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pipefd_tx[i][0], &event[0]);
        if (unlikely(ret == -1))
        {
            log_error("epoll_ctl() error: %s", strerror(errno));
            return NULL;
        }
    }

    while (1){

        n_fds = epoll_wait(epfd, event, sigshared_cfg->nf[fn_id - 1].n_threads, -1);
        if (unlikely(n_fds == -1)){

            log_error("epoll_wait() error: %s", strerror(errno));
            return NULL;
        }

        for (i = 0; i < n_fds; i++){

            bytes_read = read(event[i].data.fd, &txn, sizeof(struct http_transaction *));
            if (unlikely(bytes_read == -1)){
                log_error("read() error: %s", strerror(errno));
                return NULL;
            }

            //log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn, txn->caller_nf, txn->caller_fn, txn->rpc_handler);
            //log_info("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn, txn->caller_nf, txn->caller_fn, txn->rpc_handler);

            //ret = io_tx(txn->addr, txn->next_fn, &mapa_fd);
    	    //ret_io = io_tx_matriz(txn->addr, txn->next_fn, &mapa_fd, matriz);

	    if ( unlikely(pid == matriz[txn->next_fn][1])){
		    //log_error("Enviando sinal para ele mesmo pid:%d next_fn:%d", pid, txn->next_fn);
		    //exit(1);
	    }
	    else{
		    ret_io = io_tx_matriz(txn->addr, txn->next_fn, &mapa_fd, pid, matriz, matriz[txn->next_fn][1]);
		    if (unlikely(ret_io == -1)){
			log_error("io_tx() error");
			return NULL;
		    }
	    }
            //log_info("(ADDR TX:%ld), Route id: %u, Next Fn: %u, Caller Fn: %s (#%u) ", txn->addr, txn->route_id, txn->next_fn, txn->caller_nf, txn->caller_fn);
        }
    }

    return NULL;
}

/* TODO: Cleanup on errors */
static int nf(uint8_t nf_id){
    //const struct rte_memzone *memzone = NULL;
    pthread_t thread_worker[UINT8_MAX];
    pthread_t thread_rx;
    pthread_t thread_tx;
    uint8_t i;
    int ret;

    fn_id = nf_id;


    int pid = getpid();

    matriz[nf_id][1] = pid;
    if(unlikely( sigshared_update_map("mapa_sinal", fn_id, pid, &mapa_fd) < 0 ) ){
        printf("Erro ao atualizar mapa\n");
                return 0;
    }


    //memzone = rte_memzone_lookup(MEMZONE_NAME);
    //if (unlikely(memzone == NULL))
    //{
    //    log_error("rte_memzone_lookup() error");
    //    return -1;
    //}

    //cfg = memzone->addr;

    //ret = io_init();
    //if (unlikely(ret == -1))
    //{
    //    log_error("io_init() error");
    //    return -1;
    //}

    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pipe(pipefd_rx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }

        ret = pipe(pipefd_tx[i]);
        if (unlikely(ret == -1))
        {
            log_error("pipe() error: %s", strerror(errno));
            return -1;
        }
    }

    // IO_RX()
    ret = pthread_create(&thread_rx, NULL, &nf_rx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    // IO_TX
    ret = pthread_create(&thread_tx, NULL, &nf_tx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_create() error: %s", strerror(ret));
        return -1;
    }

    // WORKERS
    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++){
        ret = pthread_create(&thread_worker[i], NULL, &nf_worker, (void *)(uint64_t)i);
        if (unlikely(ret != 0))
        {
            log_error("pthread_create() error: %s", strerror(ret));
            return -1;
        }
    }

    /*********Espera pelas workers*********/
    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pthread_join(thread_worker[i], NULL);
        if (unlikely(ret != 0))
        {
            log_error("pthread_join() error: %s", strerror(ret));
            return -1;
        }
    }

    ret = pthread_join(thread_rx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    ret = pthread_join(thread_tx, NULL);
    if (unlikely(ret != 0))
    {
        log_error("pthread_join() error: %s", strerror(ret));
        return -1;
    }

    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = close(pipefd_rx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(pipefd_rx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(pipefd_tx[i][0]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }

        ret = close(pipefd_tx[i][1]);
        if (unlikely(ret == -1))
        {
            log_error("close() error: %s", strerror(errno));
            return -1;
        }
    }

    ret = io_exit();
    if (unlikely(ret == -1))
    {
        log_error("io_exit() error");
        return -1;
    }

    return 0;
}
/***************************************************************************/
void segfault_handler(int sig) {
    //void *array[20];
    //size_t size;

    //// Get the backtrace addresses
    //size = backtrace(array, 20);

    //fprintf(stderr, "\n[CRASH] Caught signal %d (Segmentation fault)\n", sig);
    //backtrace_symbols_fd(array, size, STDERR_FILENO);

    //_exit(1); // exit immediately, skip cleanup

    void *trace[32];
    int size = backtrace(trace, 32);
    
    fprintf(stderr, "\n[CRASH] Segmentation fault (signal %d)\n", sig);
    backtrace_symbols_fd(trace, size, STDERR_FILENO);
    fflush(stderr);
    
    _exit(1);
}

/***************************************************************************/
int main(int argc, char **argv){

    log_set_level_from_env();
    log_set_level(LOG_INFO);

    //signal(SIGSEGV, segfault_handler);
    //signal(SIGBUS, segfault_handler);
    //signal(SIGABRT, segfault_handler);

    uint8_t nf_id;
    int ret;

    //ret = rte_eal_init(argc, argv);
    //if (unlikely(ret == -1))
    //{
    //    log_error("rte_eal_init() error: %s", rte_strerror(rte_errno));
    //    goto error_0;
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

    sigemptyset(&set);       
    sigaddset(&set, SIGRTMIN+1); 
    sigprocmask(SIG_BLOCK, &set, NULL);


    //argc -= ret;
    //argv += ret;

    //if (unlikely(argc == 1))
    //{
    //    log_error("Network Function ID not provided");
    //    goto error_1;
    //}

    errno = 0;
    nf_id = strtol(argv[argc-1], NULL, 10);
    if (unlikely(errno != 0 || nf_id < 1))
    {
        log_error("Invalid value for Network Function ID");
        goto error_1;
    }

    ret = nf(nf_id);
    if (unlikely(ret == -1))
    {
        log_error("nf() error");
        goto error_1;
    }

    //ret = rte_eal_cleanup();
    //if (unlikely(ret < 0))
    //{
    //    log_error("rte_eal_cleanup() error: %s", rte_strerror(-ret));
    //    goto error_0;
    //}

    return 0;

error_1:
    printf("Erro ao inicializar nf()\n");
    //rte_eal_cleanup();
//error_0:
//    return 1;
}
