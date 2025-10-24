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

#include "../sigshared.h"


int mapa_fd;
int matriz[11][2] = {0};
sigset_t set;

#include "../include/http.h"
#include "../include/io.h"
#include "../include/spright.h"
#include "../include/utility.h"

static int pipefd_rx[UINT8_MAX][2];
static int pipefd_tx[UINT8_MAX][2];

Product products[9] = {
    {.Id = "OLJCESPC7Z",
     .Name = "Sunglasses",
     .Description = "Add a modern touch to your outfits with these sleek aviator sunglasses.",
     .Picture = "/static/img/products/sunglasses.jpg",
     .PriceUsd = {.CurrencyCode = "USD", .Units = 19, .Nanos = 990000000},
     .num_categories = 1,
     .Categories = {"accessories"}},
    {.Id = "66VCHSJNUP",
     .Name = "Tank Top",
     .Description = "Perfectly cropped cotton tank, with a scooped neckline.",
     .Picture = "/static/img/products/tank-top.jpg",
     .PriceUsd = {.CurrencyCode = "USD", .Units = 18, .Nanos = 990000000},
     .num_categories = 2,
     .Categories = {"clothing", "tops"}},
    {.Id = "1YMWWN1N4O",
     .Name = "Watch",
     .Description = "This gold-tone stainless steel watch will work with most of your outfits.",
     .Picture = "/static/img/products/watch.jpg",
     .PriceUsd = {.CurrencyCode = "USD", .Units = 109, .Nanos = 990000000},
     .num_categories = 1,
     .Categories = {"accessories"}},
    {.Id = "L9ECAV7KIM",
     .Name = "Loafers",
     .Description = "A neat addition to your summer wardrobe.",
     .Picture = "/static/img/products/loafers.jpg",
     .PriceUsd = {.CurrencyCode = "USD", .Units = 89, .Nanos = 990000000},
     .num_categories = 1,
     .Categories = {"footwear"}},
    {.Id = "2ZYFJ3GM2N",
     .Name = "Hairdryer",
     .Description = "This lightweight hairdryer has 3 heat and speed settings. It's perfect for travel.",
     .Picture = "/static/img/products/hairdryer.jpg",
     .PriceUsd = {.CurrencyCode = "USD", .Units = 24, .Nanos = 990000000},
     .num_categories = 2,
     .Categories = {"hair", "beauty"}},
    {.Id = "0PUK6V6EV0",
     .Name = "Candle Holder",
     .Description = "This small but intricate candle holder is an excellent gift.",
     .Picture = "/static/img/products/candle-holder.jpg",
     .PriceUsd = {.CurrencyCode = "USD", .Units = 18, .Nanos = 990000000},
     .num_categories = 2,
     .Categories = {"decor", "home"}},
    {.Id = "LS4PSXUNUM",
     .Name = "Salt & Pepper Shakers",
     .Description = "Add some flavor to your kitchen.",
     .Picture = "/static/img/products/salt-and-pepper-shakers.jpg",
     .PriceUsd = {.CurrencyCode = "USD", .Units = 18, .Nanos = 490000000},
     .num_categories = 1,
     .Categories = {"kitchen"}},
    {.Id = "9SIQT8TOJO",
     .Name = "Bamboo Glass Jar",
     .Description = "This bamboo glass jar can hold 57 oz (1.7 l) and is perfect for any kitchen.",
     .Picture = "/static/img/products/bamboo-glass-jar.jpg",
     .PriceUsd = {.CurrencyCode = "USD", .Units = 5, .Nanos = 490000000},
     .num_categories = 1,
     .Categories = {"kitchen"}},
    {.Id = "6E92ZMYYFZ",
     .Name = "Mug",
     .Description = "A simple mug with a mustard interior.",
     .Picture = "/static/img/products/mug.jpg",
     .PriceUsd = {.CurrencyCode = "USD", .Units = 8, .Nanos = 990000000},
     .num_categories = 1,
     .Categories = {"kitchen"}}};

static void MockListProductsResponse(struct http_transaction *txn)
{
    ListProductsResponse *out = &txn->list_products_response;

    int size = sizeof(out->Products) / sizeof(out->Products[0]);
    int i = 0;
    out->num_products = 0;
    for (i = 0; i < size; i++)
    {
        out->Products[i] = products[i];
        out->num_products++;
    }
    return;
}

// ListRecommendations fetch list of products from product catalog stub
static void ListRecommendations(struct http_transaction *txn)
{
    log_debug("[ListRecommendations] received request");

    ListProductsResponse *list_products_response = &txn->list_products_response;
    ListRecommendationsRequest *list_recommendations_request = &txn->list_recommendations_request;
    ListRecommendationsResponse *out = &txn->list_recommendations_response;

    // 1. Filter products
    strcpy(out->ProductId, list_recommendations_request->ProductId);

    // 2. sample list of indicies to return
    int product_list_size = sizeof(list_products_response->Products) / sizeof(list_products_response->Products[0]);
    int recommended_product = rand() % product_list_size;

    // 3. Generate a response.
    strcpy(out->ProductId, products[recommended_product].Id);
    return;
}

static void *nf_worker(void *arg)
{
    struct http_transaction *txn = NULL;
    ssize_t bytes_written;
    ssize_t bytes_read;
    uint8_t index;

    /* TODO: Careful with this pointer as it may point to a stack */
    index = (uint64_t)arg;

    while (1)
    {
	//printf("Entrou na nf_worker\n");
        bytes_read = read(pipefd_rx[index][0], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_read == -1))
        {
            log_error("read() error: %s", strerror(errno));
            return NULL;
        }

	//printf("Passou read()\n");
        
	if (strcmp(txn->rpc_handler, "ListRecommendations") == 0)
        {
            ListRecommendations(txn);
        }
        else
        {
            log_debug("%s() is not supported", txn->rpc_handler);
            log_debug("\t\t#### Run Mock Test ####");
            MockListProductsResponse(txn);
            ListRecommendations(txn);
            PrintListRecommendationsResponse(txn);
        }

	//printf("==recommendation(%d)== bf: next_fn:%d caller_fn:%d\n", getpid(), txn->next_fn, txn->caller_fn);
        //usleep(100); 
	//txn->next_fn = txn->caller_fn;
        //txn->caller_fn = RECOMMEND_SVC;
	
	if (txn->caller_fn != RECOMMEND_SVC){
		//printf("### next_fn:%d == caller_fn:%d ###\n", txn->next_fn, txn->caller_fn);
		//txn->next_fn = txn->caller_fn;
		txn->next_fn = FRONTEND;
	}
	txn->caller_fn = RECOMMEND_SVC;

	//printf("==recommendation(%d)== af: next_fn:%d caller_fn:%d\n\n", getpid(), txn->next_fn, txn->caller_fn);

        bytes_written = write(pipefd_tx[index][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1)){
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }
    }

    return NULL;
}

static void *nf_rx(void *arg){

    struct http_transaction *txn = NULL;
    ssize_t bytes_written;
    uint8_t i;
    //int ret;
    //uint64_t addr;

    for (i = 0;; i = (i + 1) % sigshared_cfg->nf[fn_id - 1].n_threads){
        //ret = io_rx((void **)&txn);
        //addr = io_rx(txn, sigshared_ptr, &set);
        //txn = io_rx(txn, sigshared_ptr, &set);
        io_rx((void **)&txn, sigshared_ptr, &set);
        //if (unlikely(addr == -1)){
        if (unlikely(txn == NULL)){
            log_error("io_rx() error");
            return NULL;
        }


	//txn = sigshared_mempool_access(txn, addr);
	if(unlikely(txn == NULL)){
		printf("==recommendation== ERRO mempool_access retornou NULL\n");
		return NULL;
	}


        bytes_written = write(pipefd_rx[i][1], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_written == -1))
        {
            log_error("write() error: %s", strerror(errno));
            return NULL;
        }
    }

    return NULL;
}

static void *nf_tx(void *arg)
{
    struct epoll_event event[UINT8_MAX]; /* TODO: Use Macro */
    struct http_transaction *txn = NULL;
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

    while (1)
    {
        n_fds = epoll_wait(epfd, event, sigshared_cfg->nf[fn_id - 1].n_threads, -1);
        if (unlikely(n_fds == -1))
        {
            log_error("epoll_wait() error: %s", strerror(errno));
            return NULL;
        }

        for (i = 0; i < n_fds; i++)
        {
            bytes_read = read(event[i].data.fd, &txn, sizeof(struct http_transaction *));
            if (unlikely(bytes_read == -1))
            {
                log_error("read() error: %s", strerror(errno));
                return NULL;
            }

            //log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn, txn->caller_nf, txn->caller_fn, txn->rpc_handler);
            //log_info("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u, Caller Fn: %s (#%u), RPC Handler: %s()", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn, txn->caller_nf, txn->caller_fn, txn->rpc_handler);

            //ret = io_tx(txn->addr, txn->next_fn, &mapa_fd);
    	    //ret_io = io_tx_matriz(txn->addr, txn->next_fn, &mapa_fd, matriz);
	    ret_io = io_tx_matriz(txn->addr, txn->next_fn, &mapa_fd, pid, matriz, matriz[txn->next_fn][1]);
            if (unlikely(ret_io == -1))
            {
                log_error("io_tx() error");
                return NULL;
            }
        }
    }

    return NULL;
}

/* TODO: Cleanup on errors */
static int nf(uint8_t nf_id)
{
    //const struct rte_memzone *memzone = NULL;
    pthread_t thread_worker[UINT8_MAX];
    pthread_t thread_rx;
    pthread_t thread_tx;
    uint8_t i;
    int ret;

    fn_id = nf_id;


    int pid = getpid();

    matriz[nf_id][1] = pid;
    if( sigshared_update_map("mapa_sinal", fn_id, pid, &mapa_fd) < 0  ){
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

    // IO_RX
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

    printf("Thread RX e TX atribuidas\n");
    // Cria WORKERS
    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pthread_create(&thread_worker[i], NULL, &nf_worker, (void *)(uint64_t)i);
        if (unlikely(ret != 0))
        {
            log_error("pthread_create() error: %s", strerror(ret));
            return -1;
        }
        //printf("Threads criadas: %d de %d\n", i, sigshared_cfg->nf[fn_id-1].n_threads);
    }



    printf("Passou pipes TX/RX e Workers\n");
    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pthread_join(thread_worker[i], NULL);
        if (unlikely(ret != 0))
        {
            log_error("pthread_join() error: %s", strerror(ret));
            return -1;
        }
    }


    // Espera threads
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

    //ret = io_exit();
    //if (unlikely(ret == -1))
    //{
    //    log_error("io_exit() error");
    //    return -1;
    //}

    return 0;
}


int main(int argc, char **argv)
{
    log_set_level_from_env();

    log_set_level(LOG_INFO);

    uint8_t nf_id;
    int ret;



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



    //ret = rte_eal_init(argc, argv);
    //if (unlikely(ret == -1))
    //{
    //    log_error("rte_eal_init() error: %s", rte_strerror(rte_errno));
    //    goto error_0;
    //}

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
