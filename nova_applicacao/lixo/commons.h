#ifndef COMMONS_H
#define COMMONS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
//#include <asm-generic/fcntl.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/prctl.h>

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/net_namespace.h>
#include <linux/sched.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "xsk_kern.skel.h"


/****************************************************/
#define _GNU_SOURCE
#define O_PATH		010000000
#define INVALID_UMEM_FRAME UINT64_MAX
#define NUM_FRAMES 4096
#define FRAME_SIZE 2048

#define SERVER_IP "20.20.20.1"  // Mudar IP se precisar
#define CLIENT_IP "20.20.20.2"  // Mudar IP se precisar
#define SERVER_PORT 8080

#define BUF_SIZE 2048
//#define SIMULATED_CYCLES 1600000 // Simulate ~1ms processing
//#define SIMULATED_CYCLES 75500000 // Simulate ~50ms processing
//#define SIMULATED_CYCLES 90000000 // Simulate ~50ms processing
//#define SIMULATED_CYCLES 900000000 // Simulate ~500ms processing
#define  SIMULATED_CYCLES 143300000 // 50ms isolado com 3.6GHz

#define PKT_LIMIT 100000

struct xsk_umem_info {
	struct xsk_ring_prod fq; // fill ring da UMEM
    struct xsk_ring_prod tx; // tx ring do socket
	struct xsk_ring_cons cq; // completition ring da UMEM
	struct xsk_ring_cons rx; // rx ring do socket
	struct xsk_umem *umem;

    uint32_t tx_restante;
	void *buffer; // Substituir o buffer_do_pacote por esse, para ficar mais organizado
};

struct xsk_info_global {
    //struct xsk_umem_info *umem_info;
    uint64_t *umem_frame_addr;
    uint32_t umem_frame_free;
    uint32_t ret_ring;
    uint32_t tx_restante;

};

static struct xsk_umem_config umem_cfg = {
    .fill_size = NUM_FRAMES,
    .comp_size = NUM_FRAMES,
    .frame_size = FRAME_SIZE,
    .frame_headroom = 256
    //.flags = XDP_SHARED_UMEM
    //.frame_headroom = 0,
};

static struct xsk_socket_config xsk_cfg = {
    .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS, //NUM_FRAMES,
    .tx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS, //NUM_FRAMES,
    //.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    //.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
    //.libbpf_flags = 0,
    .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    //.xdp_flags = XDP_FLAGS_SKB_MODE,
    .xdp_flags = XDP_FLAGS_DRV_MODE,
    //.bind_flags =  XDP_COPY | XDP_USE_NEED_WAKEUP,
    .bind_flags =  XDP_COPY,
    //.bind_flags =  XDP_ZEROCOPY,
};

// socket XSK2 precisa da flag XDP_SHARED_UMEM para usar a UMEM ja criada
static struct xsk_socket_config xsk_cfg2 = {
    .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS, //NUM_FRAMES,
    .tx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS, //NUM_FRAMES,
    .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    //.xdp_flags = XDP_FLAGS_SKB_MODE,
    .xdp_flags = XDP_FLAGS_DRV_MODE,
    .bind_flags =  XDP_SHARED_UMEM,
};


extern struct xsk_socket *xsk;
extern struct xsk_socket *xsk2;
extern void *buffer_do_pacote; // e usar o ptr da mem compart do shm()

extern struct xdp_program *xdp_prog;
extern struct bpf_object *bpf_obj;
extern struct bpf_map *bpf_map;
static int ifindex, lock = 1, cont_regiao = 0;

//extern char *ptr_trava;      ;  //   
extern int *ptr_trava;      ;  //   
extern char *nome_regiao     ;  // = "/memtest";
extern char *nome_trava      ;  // = "/trava";
extern char *nome_info_global;  // = "info_global";
//extern char *MSG_UDP;

static int fd_info_global, tam_info_global;
static int sig_usr1  = 10, sig_rtmin = 35;
//static pid_t fpid, ppid, pid_alvo;
extern pid_t fpid, ppid, pid_alvo;
static int long long start, end;

extern sigset_t set;
extern struct sigaction act;
extern union sigval valor;

extern struct xsk_kern_bpf    *skel;
extern struct xsk_umem_info   *umem_info;    // xsk  -- Processo
extern struct xsk_umem_info   *umem_info2;   // xsk2 -- Processo
extern struct xsk_info_global *ptr_mem_info_global;

extern int sockfd_udp;

// Socket UDP do pai
static int fd_sock_server;
static struct sockaddr_in server_addr;
static socklen_t server_len = sizeof(server_addr);

// Socket UDP do filho
extern int fd_sock_client;
extern struct sockaddr_in  client_addr;
extern socklen_t client_len; // = sizeof(client_addr);

extern char nomeproc[30];


/**************FUNCOES**********************/
void capta_sinal(int signum);
void configura_umem();
void configura_socket();
void cria_segundo_socket();

//static __always_inline uint64_t alloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free);
static __always_inline uint64_t alloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free){
    
    uint64_t frame;
    //if(frame_free == 0)
    if( ptr_mem_info_global->umem_frame_free == 0 ){
        printf("Erro em alloca_umem_frame(). umem_frame_free: %d\n", ptr_mem_info_global->umem_frame_free);
        return INVALID_UMEM_FRAME;
    }

   
    //frame = ptr_mem_info_global->umem_frame_addr[ --ptr_mem_info_global->umem_frame_free ];
    frame = ptr_mem_info_global->umem_frame_addr[ --ptr_mem_info_global->umem_frame_free ];
    ptr_mem_info_global->umem_frame_addr[ptr_mem_info_global->umem_frame_free] = INVALID_UMEM_FRAME;

    //printf("(alloca_umem)#### frame: %lu\n", frame);

	//frame = vetor_frame[--*frame_free];
	//vetor_frame[*frame_free] = INVALID_UMEM_FRAME;

    return frame;
}

static __always_inline void desaloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free, uint64_t frame);

static __always_inline __sum16 csum16_add(__sum16 csum, __be16 addend);
static __always_inline __sum16 csum16_sub(__sum16 csum, __be16 addend);
static __always_inline void csum_replace2(__sum16 *sum, __be16 old, __be16 novo);
static __always_inline int processa_pacote(uint64_t addr, uint32_t len);
static __always_inline volatile long long RDTSC();

void recebe_RX(struct xsk_info_global *info_global);
void recebe_signal_RX(struct xsk_info_global *info_global );
void recebe_pkt_RX(struct xsk_info_global *info_global );

static __always_inline int responde_pacote(uint64_t addr, uint32_t len);
void recebe_teste_RX(struct xsk_info_global *info_global);

//void complete_tx(uint64_t *vetor_frame, uint32_t *frame_free, uint32_t *tx_restante);
static __always_inline void complete_tx(uint64_t *vetor_frame, uint32_t *frame_free, uint32_t *tx_restante);

/******************NOVA_APLICACAO****************************/
static __always_inline void busy_wait_cycles(unsigned long long cycles);
static __always_inline uint16_t checksum(uint16_t *buf, int len);
/**********************************************/

#endif
