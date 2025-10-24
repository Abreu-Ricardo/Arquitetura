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
#include <uuid/uuid.h>

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

// Quote represents a currency value.
typedef struct _quote
{
    uint32_t Dollars;
    uint32_t Cents;
} Quote;

// CreateQuoteFromFloat takes a price represented as a float and creates a Price struct.
static Quote CreateQuoteFromFloat(double value)
{
    double fraction, units;
    fraction = modf(value, &units);

    Quote q = {.Dollars = (uint32_t)units, .Cents = (uint32_t)trunc(fraction * 100)};
    return q;
}

// quoteByCountFloat takes a number of items and generates a price quote represented as a float.
static double quoteByCountFloat(int count)
{
    if (count == 0)
    {
        return 0;
    }
    return 8.99;
}

// CreateQuoteFromCount takes a number of items and returns a Price struct.
static Quote CreateQuoteFromCount(int count)
{
    return CreateQuoteFromFloat(quoteByCountFloat(count));
}

// GetQuote produces a shipping quote (cost) in USD.
static void GetQuote(struct http_transaction *txn)
{
    log_debug("[GetQuote] received request");

    GetQuoteRequest *in = &txn->get_quote_request;

    // 1. Our quote system requires the total number of items to be shipped.
    int count = 0;
    int i;
    // log_debug("num_items: %d", in->num_items);
    for (i = 0; i < in->num_items; i++)
    {
        count += in->Items[i].Quantity;
    }

    // 2. Generate a quote based on the total number of items to be shipped.
    Quote quote = CreateQuoteFromCount(count);

    // 3. Generate a response.
    GetQuoteResponse *out = &txn->get_quote_response;
    strcpy(out->CostUsd.CurrencyCode, "USD");
    out->CostUsd.Units = (int64_t)quote.Dollars;
    out->CostUsd.Nanos = (int32_t)(quote.Cents * 10000000);

    return;
}

static void MockGetQuoteRequest(struct http_transaction *txn)
{
    GetQuoteRequest *in = &txn->get_quote_request;
    in->num_items = 0;

    int i;
    for (i = 0; i < 3; i++)
    {
        in->Items[i].Quantity = i + 1;
        in->num_items++;
    }

    return;
}

// getRandomLetterCode generates a code point value for a capital letter.
// static uint32_t getRandomLetterCode() {
// 	return 65 + (uint32_t) (rand() % 25);
// }

// getRandomNumber generates a string representation of a number with the requested number of digits.
// static void getRandomNumber(int digits, char *str) {
// 	char tmp[40];
// 	int i;
// 	for (i = 0; i < digits; i++) {
// 		log_debug(tmp, "%d", rand() % 10);
// 		strcat(str, tmp);
// 	}

// 	return;
// }

// CreateTrackingId generates a tracking ID.
static void CreateTrackingId(char *salt, char *out)
{
    // char random_n_1[40]; getRandomNumber(3, random_n_1);
    // char random_n_2[40]; getRandomNumber(7, random_n_2);

    // Use UUID instead of generating a tracking ID
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    uuid_unparse(binuuid, out);

    // 2. Generate a response.
    // sprintf(out, "%u%u-%ld%s-%ld%s",
    // 	getRandomLetterCode(),
    // 	getRandomLetterCode(),
    // 	strlen(salt),
    // 	random_n_1,
    // 	strlen(salt)/2,
    // 	random_n_2
    // );

    return;
}

// ShipOrder mocks that the requested items will be shipped.
// It supplies a tracking ID for notional lookup of shipment delivery status.
static void ShipOrder(struct http_transaction *txn)
{
    log_debug("[ShipOrder] received request");
    ShipOrderRequest *in = &txn->ship_order_request;

    // 1. Create a Tracking ID
    char baseAddress[100] = "";
    strcat(baseAddress, in->address.StreetAddress);
    strcat(baseAddress, ", ");
    strcat(baseAddress, in->address.City);
    strcat(baseAddress, ", ");
    strcat(baseAddress, in->address.State);

    ShipOrderResponse *out = &txn->ship_order_response;
    CreateTrackingId(baseAddress, out->TrackingId);

    return;
}

static void MockShipOrderRequest(struct http_transaction *txn)
{
    ShipOrderRequest *in = &txn->ship_order_request;
    strcpy(in->address.StreetAddress, "1600 Amphitheatre Parkway");
    strcpy(in->address.City, "Mountain View");
    strcpy(in->address.State, "CA");
    strcpy(in->address.Country, "United States");
    in->address.ZipCode = 94043;
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
        bytes_read = read(pipefd_rx[index][0], &txn, sizeof(struct http_transaction *));
        if (unlikely(bytes_read == -1))
        {
            log_error("read() error: %s", strerror(errno));
            return NULL;
        }

        if (strcmp(txn->rpc_handler, "ShipOrder") == 0)
        {
            ShipOrder(txn);
        }
        else if (strcmp(txn->rpc_handler, "GetQuote") == 0)
        {
            GetQuote(txn);
        }
        else
        {
            log_debug("%s() is not supported", txn->rpc_handler);
            log_debug("\t\t#### Run Mock Test ####");
            MockShipOrderRequest(txn);
            ShipOrder(txn);
            PrintShipOrderResponse(txn);
            MockGetQuoteRequest(txn);
            GetQuote(txn);
            PrintGetQuoteResponse(txn);
        }


	//printf("==shipping(%d)== bf: next_fn:%d caller_fn:%d\n", getpid(),txn->next_fn, txn->caller_fn);
        //usleep(100); 
        //txn->next_fn = txn->caller_fn;
        //txn->caller_fn = SHIPPING_SVC;
	
	if (txn->caller_fn != SHIPPING_SVC){
		//printf("### next_fn:%d == caller_fn:%d ###\n",  txn->next_fn, txn->caller_fn);
		//txn->next_fn = txn->caller_fn;
		txn->next_fn = FRONTEND;
	}
	txn->caller_fn = SHIPPING_SVC;

	//printf("==shipping(%d)== af: next_fn:%d caller_fn:%d\n\n", getpid(), txn->next_fn, txn->caller_fn);

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
        //    log_error("io_rx() error");
        //    return NULL;
        //}


	//txn = sigshared_mempool_access(txn, addr);
	if(unlikely(txn == NULL)){
		printf("==shipping== ERRO mempool_access retornou NULL\n");
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

            //log_debug("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);
            //log_info("Route id: %u, Hop Count %u, Next Hop: %u, Next Fn: %u", txn->route_id, txn->hop_count, sigshared_cfg->route[txn->route_id].hop[txn->hop_count], txn->next_fn);

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

    // Cria workers
    for (i = 0; i < sigshared_cfg->nf[fn_id - 1].n_threads; i++)
    {
        ret = pthread_create(&thread_worker[i], NULL, &nf_worker, (void *)(uint64_t)i);
        if (unlikely(ret != 0))
        {
            log_error("pthread_create() error: %s", strerror(ret));
            return -1;
        }
    }

    // Espera as workers
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

    //ret = io_exit();
    //if (unlikely(ret == -1))
    //{
    //    log_error("io_exit() error");
    //    return -1;
    //}

    return 0;
}



int main(int argc, char **argv){
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
