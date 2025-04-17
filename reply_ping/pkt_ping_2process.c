#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
//#include <asm-generic/fcntl.h>

#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>


//#include <bpf/xsk.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

//#include <bpf/xsk.h>

#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/bpf.h>
#include <linux/ip.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <assert.h>

#include <linux/net_namespace.h>
#include <linux/sched.h>
#include <pthread.h>


#include "xsk_kern.skel.h"

/******************************************************************************/
#define _GNU_SOURCE
#define O_PATH		010000000
#define INVALID_UMEM_FRAME UINT64_MAX
#define NUM_FRAMES 4096
#define FRAME_SIZE 2048

//#define NUM_FRAMES 8192
//#define NUM_FRAMES 2048
//#define FRAME_SIZE 4096
//
#define SERVER_IP "20.20.20.1"  // Mudar IP se precisar
#define CLIENT_IP "20.20.20.2"  // Mudar IP se precisar
#define SERVER_PORT 8080


struct xdp_program *xdp_prog;
struct bpf_object *bpf_obj;
struct bpf_map *bpf_map;

int ifindex;
int lock = 1;
int cont_regiao = 0;

char *nome_regiao = "/memtest";
char *nome_trava  = "/trava";
char *nome_info_global = "info_global";
//char *ptr_trava;
int *ptr_trava;

int fd_info_global; 
int tam_info_global;

int long long start;
int long long end;

pid_t fpid;
pid_t ppid;

sigset_t set;
int sig = 10;


// Socket UDP do pai
int fd_sock_server;
struct sockaddr_in server_addr;
socklen_t server_len = sizeof(server_addr);

// Socket UDP do filho
int fd_sock_client;
struct sockaddr_in server_addr_c, client_addr;
socklen_t client_len = sizeof(client_addr);


static char MSG_UDP[30] = "PODE IR";


//struct info_ebpf bpf;
// Estrutura de dados para configurar a umem do socket
struct xsk_umem_config umem_cfg = {
    .fill_size = NUM_FRAMES,
    .comp_size = NUM_FRAMES,
    .frame_size = FRAME_SIZE,
    .frame_headroom = 256
    //.flags = XDP_SHARED_UMEM
    //.frame_headroom = 0,
};

/*****************************************/
// Estrutura de dados para configurar e usar a UMEM
struct xsk_umem_info {
	struct xsk_ring_prod fq; // fill ring da UMEM
    struct xsk_ring_prod tx; // tx ring do socket
	struct xsk_ring_cons cq; // completition ring da UMEM
	struct xsk_ring_cons rx; // rx ring do socket
	struct xsk_umem *umem;

    uint32_t tx_restante;
	void *buffer; // Substituir o buffer_do_pacote por esse, para ficar mais organizado
};

struct xsk_umem_info *umem_info;    // xsk  -- Processo
struct xsk_umem_info *umem_info2;   // xsk2 -- Processo

/*****************************************/
struct xsk_info_global {
    //struct xsk_umem_info *umem_info;
    uint64_t *umem_frame_addr;
    uint32_t *umem_frame_free;
    uint32_t ret_ring;
    uint32_t tx_restante;

};

struct xsk_info_global *ptr_mem_info_global;
struct xsk_kern_bpf *skel;


void polling_RX(struct xsk_info_global *info_global);

/*****************************************/

// Configuracoes do socket XSK
struct xsk_socket_config xsk_cfg = {
    .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS, //NUM_FRAMES,
    .tx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS, //NUM_FRAMES,
    //.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    //.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
    //.libbpf_flags = 0,
    .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    //.xdp_flags = XDP_FLAGS_SKB_MODE,
    .xdp_flags = XDP_FLAGS_DRV_MODE,
    .bind_flags =  XDP_COPY | XDP_USE_NEED_WAKEUP,
    //.bind_flags =  XDP_COPY,
};

// socket XSK2 precisa da flag XDP_SHARED_UMEM para usar a UMEM ja criada
struct xsk_socket_config xsk_cfg2 = {
    .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS, //NUM_FRAMES,
    .tx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS, //NUM_FRAMES,
    .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    //.xdp_flags = XDP_FLAGS_SKB_MODE,
    .xdp_flags = XDP_FLAGS_DRV_MODE,
    //.bind_flags =  XDP_SHARED_UMEM,
    .bind_flags =  XDP_SHARED_UMEM | XDP_USE_NEED_WAKEUP,
};

struct xsk_socket *xsk;
struct xsk_socket *xsk2;

void *buffer_do_pacote; // e usar o ptr da mem compart do shm()

/*************************************************************************/
static __always_inline volatile long long RDTSC() {
    
    //register long long TSC asm("eax");
    //asm volatile (".byte 15, 49" : : : "eax", "edx");
    //return TSC;

    unsigned int lo, hi;
    
    asm ("rdtsc" : "=a" (lo), "=d" (hi)); // Execute RDTSC and store results
    return ((long long)hi << 32) | lo;            // Combine high and low parts
} 


static void complete_tx(uint64_t *vetor_frame, uint32_t *frame_free, uint32_t *tx_restante);

/************************************************************************/
static void capta_sinal(int signum){
    //getchar();

    if (signum == 2){

        bpf_map__unpin( bpf_object__find_map_by_name( skel->obj , "mapa_fd") , "/home/ubuntu/Documents/Arquitetura/dados/mapa_fd");  
        bpf_map__unpin( bpf_object__find_map_by_name( skel->obj , "xsk_map") , "/home/ubuntu/Documents/Arquitetura/dados/xsk_map");

        //xdp_program__detach(xdp_prog, 2, XDP_MODE_SKB, 0);
        //xdp_program__detach(xdp_prog, 2, XDP_MODE_NATIVE, 0);
        //xdp_program__close(xdp_prog);

        xsk_kern_bpf__destroy(skel);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        
        // Free a block allocated by \`malloc', \`realloc' or \`calloc'.
        // free(buffer_do_pacote);

        printf("\nPrograma Removido!\n");
        shm_unlink(nome_regiao);
        shm_unlink(nome_trava);
        shm_unlink(nome_info_global );
       
        system("xdp-loader unload veth2 --all");
        system("xdp-loader status");
        system("rm /home/ubuntu/Documents/Arquitetura/dados/xsk_kern_rodata");
 //       system("rm /home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_fd");
//        system("rm /home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/xsk_map");
        system("killall pktping_2proc");
        
        lock = 0;
	    exit(1);
    }

    //else if( signum == 10){
    //    //polling_RX( ptr_mem_info_global );
    //    printf("---->ENTREI AQUI NO CAPTA_SINAL COM VALOR 10<-----\n");
    //     complete_tx(ptr_mem_info_global->umem_frame_addr, 
    //                        ptr_mem_info_global->umem_frame_free, 
    //                        &ptr_mem_info_global->tx_restante); 
    //}
    return;
}

/************************************************************************/
void configura_umem(){

    // Aumentando o limite de recurso que o processo pode usar
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("Erro ao configurar limite de memória bloqueada");
        exit(1);
    }

    // Alocação de memória para o UMEM
    int tam_buffer_pkt = NUM_FRAMES * FRAME_SIZE;
    int ret_umem_create;
    struct xsk_umem_info *teste;
    umem_info = calloc(1, sizeof(*teste )/*sizeof(struct xsk_umem_info *)*/);
    ret_umem_create = xsk_umem__create(&umem_info->umem, buffer_do_pacote, NUM_FRAMES * FRAME_SIZE, &umem_info->fq, &umem_info->cq, &umem_cfg);
    
    // testando ultimo parametro como NULL, parametro de config, assim, temos a config padrao
    // ret_umem_create = xsk_umem__create(&umem_info->umem, buffer_do_pacote, NUM_FRAMES * FRAME_SIZE, &umem_info->fq, &umem_info->cq, NULL);
    if ( ret_umem_create < 0 ) {
        fprintf(stderr, "Erro ao criar UMEM: %s\n", strerror(errno));
        free(buffer_do_pacote);
        exit(1);
    }
   return;
}

/************************************************************************/
void configura_socket(const char *iface ){
    int sock_fd;
    int index;    // Configuração do socket AF_XDP

    // Para o pkt ser redirecionado eh preciso atualizar o mapa xsk com o fd do socket a ser redirecionado
    // apenas o socket xsk2 eh usado
    if (xsk_socket__create(&xsk, iface, 0, umem_info->umem, &umem_info->rx, &umem_info->tx, &xsk_cfg) < 0) {
        fprintf(stderr, "Erro ao criar socket XDP: %s\n", strerror(errno));
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        exit(1);
    }
    
    sock_fd = xsk_socket__fd(xsk);
    index = 0;
    printf("\nValor do fd do socket xsk: %d\n\n", sock_fd);

    if (sock_fd < 0){
        fprintf(stderr, "Erro ao pegar o fd do socket xsk\n");
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_DRV_MODE, 0);
        xdp_program__close(xdp_prog);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        exit(1);
 
    }
    return;
}

/************************************************************************/
void cria_segundo_socket(const char *iface){
    __u32  ret_lookup, ret_lookup2, key=0; 
    int ret, ret_update;
    int map_fd_fd2;
    
    // Aloca umem_info2 para ser usado no socket2
    umem_info2 = calloc(1, sizeof(*umem_info2));
	if (!umem_info2){
        printf("erro ao alocar umem_info2 na func cria_segundo_socket()\n");
		return;
    }
    /*******************/

    // Cria socket compartilhado
    ret = xsk_socket__create_shared(&xsk2, iface, 0, umem_info->umem, &umem_info2->rx, &umem_info2->tx, &umem_info->fq, &umem_info->cq, &xsk_cfg2);
    if (ret < 0) {
        printf("Valor do ret de socket_shared: %d\n", ret);
        fprintf(stderr, "Erro ao criar socket XDP: %s\n", strerror(errno));
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        exit(1);
    }
    printf("Segundo socket criado!\n");
    /********************/

    int map_fd_xsk = bpf_object__find_map_fd_by_name( skel->obj , "xsk_map");

    // Na implementacao eh usado um bpf_map_update_elem mas na chave eh 
    // usado o id da fila(queue_id), por isso que qnd eu tento fazer na mao da erro
    // socket que eh utilizado eh o xsk2, por isso o pkt eh redirecionado para o
    // socket xsk2
    ret_update = xsk_socket__update_xskmap(xsk2, map_fd_xsk);
    if (ret_update < 0){
        fprintf(stderr, "Erro ao atualizar o mapa xsk_map\n");
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_DRV_MODE, 0);
        //xdp_program__close(xdp_prog);
        xsk_kern_bpf__destroy(skel);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
    }

    int sock_fd2 = xsk_socket__fd(xsk2);
    printf("Valor do fd do segundo socket: %d\n", sock_fd2);
}

/************************************************************************/
static uint64_t alloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free){
    
    uint64_t frame;
    if(frame_free == 0)
        return INVALID_UMEM_FRAME;
    
	frame = vetor_frame[--*frame_free];
	vetor_frame[*frame_free] = INVALID_UMEM_FRAME;

    return frame;
}

/****************************************************************************/
static void desaloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free, uint64_t frame){
	assert(*frame_free < NUM_FRAMES);
	vetor_frame[*frame_free++] = frame;
}

/****************************************************************************/
static __always_inline __sum16 csum16_add(__sum16 csum, __be16 addend){
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

/****************************************************************************/
 static __always_inline __sum16 csum16_sub(__sum16 csum, __be16 addend){
	return csum16_add(csum, ~addend);
}

/****************************************************************************/
static __always_inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new){
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}
/*************************************************************************/
static int processa_pacote(uint64_t addr, uint32_t len){
    // Allow to get a pointer to the packet data with the Rx descriptor, in aligned mode.
  
    /******************************************************/
    //start = RDTSC();
    // Primeiro pacote demora uns 5K ciclos, dai pra frente demora 10-20 ciclos
    uint8_t *pkt = xsk_umem__get_data(buffer_do_pacote, addr);
    //end = RDTSC();
    /******************************************************/

    /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
     *
     * Some assumptions to make it easier:
     * - No VLAN handling
     * - Only if nexthdr is ICMP
     * - Just return all data with MAC/IP swapped, and type set to
     *   ICMPV6_ECHO_REPLY
     * - Recalculate the icmp checksum */
    
    //start = RDTSC();
    // Primeiro pkt demora 12K ciclos, dai pra frente menos de 800ciclos
    /******************************************************/
    int ret;
    uint32_t tx_idx = 0;
    uint8_t tmp_mac[ETH_ALEN];
    
    struct in_addr tmp_ip;
    struct ethhdr  *eth = (struct ethhdr *) pkt;
    struct iphdr   *ip  = (struct iphdr  *) (eth + 1);
    struct icmphdr *icmph = (struct icmphdr *) (ip + 1);
    
    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    memcpy(&tmp_ip, &ip->saddr, sizeof(tmp_ip));
    memcpy(&ip->saddr, &ip->daddr, sizeof(tmp_ip));
    memcpy(&ip->daddr, &tmp_ip, sizeof(tmp_ip));

    icmph->type = ICMP_ECHOREPLY;

    //csum_fold_helper_ip(icmph->checksum);
    csum_replace2(&icmph->checksum, htons(ICMP_ECHO << 8 ), htons(ICMP_ECHOREPLY << 8 ));
    
    /******************************************************/
   // end = RDTSC();

    /* Here we sent the packet out of the receive port. Note that
     * we allocate one entry and schedule it. Your design would be
     * faster if you do batch processing/transmission */

    // Reserve one or more slots in a producer ring.
    // __u32 number of slots that were successfully reserved (idx) on success, or a 0 in case of failure.
    
    // Primeiro pkt demora 3K ciclos, dai pra frente menos de 300 ciclos
    //start = RDTSC();
    /******************************************************/
    ret = xsk_ring_prod__reserve(&umem_info2->tx, 1, &tx_idx);
    if (ret != 1) {
        /* No more transmit slots, drop the packet */
        return true; // se retornar false a inversao de sinal vai desalocar
    }

    xsk_ring_prod__tx_desc(&umem_info2->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&umem_info2->tx, tx_idx)->len = len;
    xsk_ring_prod__submit( &umem_info2->tx, 1);
    //umem_info->tx_restante++;
    
    //info_global-> tx_restante++;
    ptr_mem_info_global->tx_restante++;

    //end = RDTSC();
    /******************************************************/


    
    //printf("tempo total da func processa_pacote() --> %lld\n", (end - start) );
    //printf("###(processa_pacote) umem_info->tx_restante: %d\n", ptr_mem_info_global->tx_restante);
    //return true;
    return false;
}

/*************************************************************************/
int cont = 0;

int i, retsend; 
unsigned int completed;
uint32_t idx_cq;

static void complete_tx(uint64_t *vetor_frame, uint32_t *frame_free, uint32_t *tx_restante){
    //printf("chamando complete_tx: %d\n", cont);
    //cont++;
    
    //start = RDTSC();

    int i, retsend; 
    unsigned int completed;
	uint32_t idx_cq;
	
    if (!*tx_restante){
	    //printf("\n\n###(complete_tx) nao enviou o pkt, umem_info->tx_restante: %d\n", *tx_restante);
        return;
    }
    //printf("\n\nPassou do !umem_info->tx_restante, valor: %d\n", umem_info->tx_restante); 
    
    //sendto() --> Demora mais q tudo nessa func, 18000 ciclos
    retsend = sendto(xsk_socket__fd(xsk2), NULL, 0, MSG_DONTWAIT, NULL, 0);
    //printf("Retorno do sendto: %d\n", retsend);

    // Se retorno de sendto for < 0, houve erro 
    if (retsend >= 0){

        //printf("ret sendto: %d\n", retsend);
        /* Collect/free completed TX buffers */

        // Tem hora que leva 40 ciclos outras 1000+
        completed = xsk_ring_cons__peek(&umem_info->cq,	XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);
       
        //printf("(complete_tx) valor de completed: %d\n", completed);
        if (completed > 0) {
            //printf("-->Entrou no completed<--\n");
            for (i = 0; i < completed; i++){
                //printf("Desalocando %d\n", i);
                desaloca_umem_frame(vetor_frame, frame_free, *xsk_ring_cons__comp_addr(&umem_info->cq, idx_cq++) );
            }
            xsk_ring_cons__release(&umem_info->cq, completed);
            *tx_restante -= completed < *tx_restante ?	completed : *tx_restante;
        }
    }
    else{
         printf("ERRO, retorno do sendto() menor que 0, valor: %d\n\n", retsend);
         printf("*****************************\n\n");
    }

    //end = RDTSC();
    kill( fpid , SIGUSR1 ); 
    //printf("tempo final da func complete_tx() --> %f\n", (end - start) / 3.6 );
    //printf("----- Terminou complete_tx() ------\n");
    return;
}

/*************************************************************************/
// info_global == ptr_mem_info_global
void polling_RX(struct xsk_info_global *info_global ){
    //pid_t tid = pthread_self();
    //printf("<Entrou polling_RX com a thread:%ld>\n", /*gettid()*/ syscall(SYS_gettid));
    //printf("<Entrou em polling_RX>\n");
    
    /**************************************************************/
    int i =0;

    __u32 ret_ring=0, stock_frames=0;
    __uint64_t cont_pkt=0;
   
    uint32_t idx_rx = 0;
    uint32_t idx_fq = 0;
    uint64_t addr;
    uint32_t len; 
   
    //ret_ring = xsk_ring_cons__peek(&umem_info2->rx, 64, &idx_rx);

    while( 1 ){

            //if(*ptr_trava == 0){ 
            //while (lock == 1) {
            // esse laco pode ser o equivalente a funcao handle_receive_packets
            // do advanced03-AF-XDP
            idx_rx = 0;
            idx_fq = 0;
            i = 0;

            // Verifica se há pacotes no ring buffer de recepção
            // xsk_ring_cons_peek(ANEL_RX, tam_do_lote, )
            // Essa funcao no exemplo advanced03 tbm retorna 0
            ret_ring = xsk_ring_cons__peek(&umem_info2->rx, 64, &idx_rx);

            //printf("\nVALOR DO ret_ring %d\n", ret_ring);
            //printf("valor do umem_frame_free: %d\n", *info_global->umem_frame_free);

            if( !ret_ring ){
                //printf("\n\n<PROC_FILHO> <ret_ring deu zero>\n");
                //sigwait( &set , &sig );
                continue;
            }

            // Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
            // retorna o endereco do pacote --> __u64 address of the packet.
            stock_frames = xsk_prod_nb_free(&umem_info->fq,	*info_global->umem_frame_free);
            //printf("******************VALOR DO stock_frames %d\n", stock_frames);

            if(stock_frames > 0){
                //printf("stock_frames OK ret_ring %d\n", ret_ring);
                // Reserve one or more slots in a producer ring.
                // retorna --> __u32 number of slots that were successfully reserved (idx) on success, or a 0 in case of failure.
                int ret_res = xsk_ring_prod__reserve(&umem_info->fq, stock_frames, &idx_fq);

                /* This should not happen, but just in case */
                while (ret_res != stock_frames)
                    ret_res = xsk_ring_prod__reserve(&umem_info->fq, ret_ring, &idx_fq);

                for (i = 0; i < stock_frames; i++){
                    //Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
                    *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(info_global->umem_frame_addr, info_global->umem_frame_free);
                }
                // Submit the filled slots so the kernel can process them
                xsk_ring_prod__submit(&umem_info->fq, stock_frames);
            }


            /* Process received packets */
            for (i = 0; i < ret_ring; i++) {
                // xsk_ring_cons__rx_desc() --> This function is used to retrieve the receive descriptor at a specific index in the Rx ring
                addr = xsk_ring_cons__rx_desc(&umem_info2->rx, idx_rx)->addr;
                len  = xsk_ring_cons__rx_desc(&umem_info2->rx, idx_rx++)->len;

                //cont_pkt++;
                //printf("Tamanho do pacote recebido %d | num pkt:%ld\n", len, cont_pkt);

                // CHAMA PROCESSA_PACOTE
                //if (!processa_pacote(umem_info,  addr, len)){
                if ( !processa_pacote( addr, len) ){
                    desaloca_umem_frame(info_global->umem_frame_addr, info_global->umem_frame_free, addr);
                }
             }


            /*********************/
            //*ptr_trava = 1;
            
            // Envia sinal para o processo pai para enviar os pkts
            if ( sendto(fd_sock_client, MSG_UDP, sizeof(MSG_UDP), 0, (struct sockaddr *)&client_addr, client_len)  < 0 ){
                perror("\t\t### <PROC_FILHO>Erro ao enviar pkt para o proc_pai ###");
                capta_sinal( SIGINT );
            }
            else{ 
                //printf("<PROC_FILHO>Enviando pkt para o pai(%d)...-->\n", ppid);
                //printf("<PROC_FILHO>Esperando pkt do pai...\n");
                
            if( recvfrom( fd_sock_client, MSG_UDP, sizeof(MSG_UDP), 0, (struct sockaddr *)&client_addr, &client_len) < 0  ){
                printf("<PROC_FILHO>Pkt do PAI recebido...<--\n\n");
                continue;
            }

            } 
        }
}




/*************************************************************************/
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
   
    /***************Config da regiao de mem compart com shm*****************/
    char *caminho_prog = "xsk_kern.o";
    char *ptr_fim_regiao;
    uint64_t  *ptr_regiao;
    
    signal(SIGINT, capta_sinal);


    int mapa_fd, map_fd_xsk,
        fd_mapa_fd, fd_trava,
        fd_namespace,
        fd_shm;

    int chave = 0, valor, retorno;       
    int tam_trava = 100,
        tam_regiao = NUM_FRAMES * FRAME_SIZE;

    int key = 0, ret_xsk = -1;
    
    // Vars de retorno
    char *ret_lookup = "valor inicial"; // valor para ver se escreveu algo na var
    int ret_attach, 
        ret_look, 
        ret_xskmap, 
        ret_reserve, 
        ret_ring, 
        ret_sys;

    
    unsigned int stock_frames;
   

    struct xsk_info_global *info_global;

    // Trava para ver se ainda ha espaco para os consumir frames
    uint32_t umem_frame_free = NUM_FRAMES;


    __u32 idx;
    uint64_t umem_frame_addr[NUM_FRAMES];
    
    pid_t pid;



    /***********************************************************************/
    // Carrega e anexa o programa XDP usando libxdp
    ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		printf("Erro ao converter o nome da interface para indice\n");
		return 1;
	}

    // Abre e carrega o programa usando o skeleton
    skel = xsk_kern_bpf__open_and_load();
    if (!skel){
        perror("Erro ao abrir/carregar programa");
        xsk_kern_bpf__destroy(skel);
    }

    skel->links.xdp_prog = bpf_program__attach_xdp( skel->progs.xdp_prog , ifindex );

    printf("Indice da interface %d\n",ifindex);
	// load XDP object by libxdp 
	//xdp_prog = xdp_program__open_file(caminho_prog, "xdp", NULL);
	//if (!xdp_prog) {
	//	printf("Erro ao abrir o programa xdp\n");
	//	return 1;
	//}

	// attach XDP program to interface with xdp mode
	// Please set ulimit if you got an -EPERM error.
	//int ret_attach = xdp_program__attach(xdp_prog, ifindex, XDP_MODE_SKB, 0);
	//ret_attach = xdp_program__attach(xdp_prog, ifindex, XDP_MODE_NATIVE, 0);
	//if (ret_attach) {
	//	printf("Error, Set xdp fd on %d failed\n", ifindex);
	//	return ret_attach;
	//}

	// Find the map fd from the bpf object
    // Pega um bpf_object a partir da struct xdp_program
	//bpf_obj = xdp_program__bpf_obj(xdp_prog);
	
    //bpf_obj = bpf_object__open_file(caminho_prog, NULL);
    //if (bpf_obj == NULL){
    //    perror("Erro ao abrir o arquivo para bpf_object");
    //}
	
    //int mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "mapa_fd");
    // Pega o fd do mapa
	mapa_fd = bpf_object__find_map_fd_by_name( skel->obj, "xsk_map"); 
	if (mapa_fd < 0) {
		printf("Erro ao tentar obter o fd do mapa pelo bpf_obj, retorno: %d\n", mapa_fd);
        bpf_object__close(bpf_obj);
		return mapa_fd;
	}
 
    //map_fd_xsk = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(xdp_prog), "xsk_map");
    map_fd_xsk = bpf_object__find_map_fd_by_name( skel->obj , "xsk_map");
    if (map_fd_xsk < 0) {
        fprintf(stderr, "Erro ao encontrar o mapa xsk_map\n");
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_DRV_MODE, 0);
        //xdp_program__close(xdp_prog);
        xsk_kern_bpf__destroy(skel);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }

    bpf_object__pin_maps( /*bpf_obj*/ skel->obj , "/home/ubuntu/Documents/Arquitetura/dados");
    //int fd_mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "mapa_fd");
    fd_mapa_fd = bpf_obj_get("/home/ubuntu/Documents/Arquitetura/dados/mapa_fd"); 
    retorno    = bpf_map_update_elem(fd_mapa_fd, &chave, &nome_regiao, BPF_ANY );
    bpf_map    = bpf_object__find_map_by_name(skel->obj, "xsk_map");

    printf("\nfd do mapa xsk: %d\n", map_fd_xsk);
    printf("-->fd do fd_mapa_fd: %d\n", fd_mapa_fd);

    /*********************************************CRIA REGIAO MEMTEST*****************************************************************/

    //int fd_shm = shm_open(nome_regiao, O_CREAT | O_RDWR, 0666);
    fd_shm = shm_open(nome_regiao, O_CREAT | O_RDWR, 0777);
    if (fd_shm == -1){
        perror("Erro em shm_open\n");
        exit(1);
    }

    // Tamanho da regiao de mem.
    
    // Atribuindo tamanho para a regiao de mem. compart.
    int ret_ftruncate = ftruncate(fd_shm, tam_regiao);
    if ( ret_ftruncate == -1 ){
        perror("Erro em ftruncate\n");
        exit(1);
    }
    buffer_do_pacote   = ( void *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);

    /************************************************** Cria mem da trava ************************************************************/


    fd_trava = shm_open(nome_trava, O_CREAT | O_RDWR, 0777);
    if (fd_trava == -1){
        perror("Erro em shm_open\n");
        exit(1);
    }
    
    tam_trava = sizeof(int);
    // Atribuindo tamanho para a regiao de mem. compart.
    int retorno_ftruncate = ftruncate(fd_trava, tam_trava);
    if ( ret_ftruncate == -1 ){
        perror("Erro em ftruncate na tam_trava\n");
        exit(1);
    }
    
    //ptr_trava = (char *) mmap(0, tam_trava, PROT_WRITE, MAP_SHARED, fd_trava, 0);
    ptr_trava = (int *) mmap(0, tam_trava, PROT_WRITE, MAP_SHARED, fd_trava, 0);
    //*ptr_trava = 0;
    

    /*###############################CRIAÇÃO DA REGIÃO DE MEM COMPART MEM_INFO_GLOBAL###################################################*/
    
    ptr_mem_info_global = (struct xsk_info_global *) malloc( sizeof(struct xsk_info_global));

    fd_info_global = shm_open(nome_info_global, O_CREAT | O_RDWR, 0777);
    if (fd_info_global == -1){
        perror("Erro em shm_open de info_global\n");
        exit(1);
    }

    tam_info_global = sizeof(struct xsk_info_global) * 100;

    ret_ftruncate = ftruncate(fd_info_global, tam_regiao);
    if ( ret_ftruncate == -1 ){
        perror("Erro em ftruncate\n");
        exit(1);
    }

    ptr_mem_info_global   = ( struct xsk_info_global *) mmap(0, tam_info_global, PROT_WRITE, MAP_SHARED, fd_info_global, 0);

    /*###############################FIM DO CARREGAMENTO DO PROGRAMA###################################################*/
    
    configura_umem();
    configura_socket( iface );
    cria_segundo_socket( iface );

    /*###############################FIM CONFIGS DA UMEM E SOCKET###################################################*/


    ret_look = bpf_map_lookup_elem(fd_mapa_fd, &key, &ret_lookup);
    ret_xskmap = bpf_map_lookup_elem(map_fd_xsk, &key, &ret_xsk);
    
    if(ret_look < 0 && ret_xskmap < 0){
        printf("DEU ERRADO OLHAR O MAPA: %d\n", ret_look);
        return -1;
    }

    printf("\nValor do retorno do mapa: %s\n", ret_lookup);
    printf("Valor do retorno do xskmap: %d\n", ret_xskmap);
    printf("Socket XDP configurado com sucesso na interface %s.\n\n", iface);

    /**************************************************************************************************************/



    /* ########################################CONFIG DOS ANEIS#################################################### */


    // Alocando o offset para os frames para os blocos da UMEM
	for (int i = 0; i < NUM_FRAMES; i++){
		umem_frame_addr[i] = i * FRAME_SIZE;
    }

    
    // Enchendo o caminho de recebimento com buffers
    // Salva o valor de buffers reservados em idx
    // #1 dando blocos p/ o kernel, atualizando o FILL queue e incrmentando produtor/head
    ret_reserve = xsk_ring_prod__reserve(&umem_info->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    //printf("VALOR DO ret_reserve %d valor do idx:%d\n\n", ret_reserve, idx);
    if( ret_reserve !=  XSK_RING_PROD__DEFAULT_NUM_DESCS){
        printf("Erro ao reservar buffer FILL, ret_reserve != XSK_RING_PROD__DEFAULT_NUM_DESCS\n");
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_DRV_MODE, 0);
        //xdp_program__close(xdp_prog);
        xsk_kern_bpf__destroy(skel);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }
    
    // Carregando os buffers
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++){
    	//xsk_ring_prod__fill_addr() --> Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.

        //retorna o endereco do pacote
        *xsk_ring_prod__fill_addr(&umem_info->fq, idx++) = alloca_umem_frame(umem_frame_addr, &umem_frame_free);
    }

    // xsk_ring_prod__submit() --> Submit the filled slots so the kernel can process them.
   	xsk_ring_prod__submit(&umem_info->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
    
    
    info_global = (struct xsk_info_global *) malloc( sizeof(*info_global ) );
   
    info_global->umem_frame_addr = umem_frame_addr;
    info_global->umem_frame_free = &umem_frame_free;
    info_global->ret_ring        = ret_ring;

    // Apos o fork essa var(ptr_mem_info_global) fica compartilhada entre os dois processos
    memcpy(ptr_mem_info_global , info_global , sizeof(*info_global));
    printf("------------ umem_frame_addr[2]:%ld\n", ptr_mem_info_global->umem_frame_addr[2]);



    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGUSR1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q ode "ouvir"
    sigprocmask(SIG_BLOCK, &set, NULL);  // Aplica o conjunto q pode "ouvir"

    //signal( SIGUSR1 , capta_sinal );
    ppid = getpid();
    // ############################## CRIANDO SOCKETS PARA ENVIO DE UDP #############################
    
    // Cria socket UDP
    if ((fd_sock_server = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("FALHA ao criar Socket UDP");
        exit(EXIT_FAILURE);
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;
    server_addr.sin_port        = htons(SERVER_PORT);
    //server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_addr.s_addr = INADDR_ANY;


    //if (bind(fd_sock_server, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    //    perror("Falha no Bind do Socket");
    //    close(fd_sock_server);
    //    exit(EXIT_FAILURE);
    //}
    
    
    // ############################## FIM SOCKETS PARA ENVIO DE UDP #############################

    pid = fork();

    // ############################## PROCESSAMENTO DOS PACOTE #############################
    

    // Processo filho
    if( pid == 0){
         // Trocando o nome do processo para poolpingPAI
        strncpy(argv[0], "udp_FIL", strlen(argv[0]));       

        fpid = getpid();
        char settar_cpuf[30];

        // Atribui o valor do PID do filho para que o proc pai consiga enviar o sinal
        memcpy(ptr_trava, &fpid, sizeof(fpid));


        printf("\n<PID DO FILHO %d>\n", fpid);
        if( setsid() < 0 ){
            exit(-1);
        }

        // PID do namespace pego com lsns --type=net dentro do container
        fd_namespace = open( "/proc/6962/ns/net",  O_RDONLY );
        ret_sys = syscall( __NR_setns, fd_namespace ,  CLONE_NEWNET /*0*/ );
        if (ret_sys < 0){
            printf("+++ Verificar se o processo do container esta correto. Checar com 'lsns --type=net +++'\n");
            perror("\n\nNao foi possivel mover o processo");
        }


        // Create UDP socket
        if ( (fd_sock_client = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
            perror("Falha ao criar Socket UDP do PROC_FILHO");
            exit(EXIT_FAILURE);
        }

        // Bind endereco e porta
        memset(&client_addr, 0, sizeof(client_addr));
        client_addr.sin_family = AF_INET;
        //client_addr.sin_addr.s_addr = INADDR_ANY;
        client_addr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_IP, &client_addr.sin_addr);

        //if( bind(fd_sock_client, (struct sockaddr*)&client_addr, sizeof(client_addr)) ){
        //    perror("Erro no BIND do PROC_FILHO");
        //    capta_sinal( 2 );
        //}


        sprintf(settar_cpuf, "taskset -cp 5 %d", fpid);
        system(settar_cpuf);

        printf("RETORNO DA SYSCALL DO FILHO -->> %d\n\n", ret_sys);
        printf("PROCESSO FILHO CRIADO E NA CPU 5\n");

        polling_RX( ptr_mem_info_global );
    }

    // Processo pai
    else if ( pid > 0){
        // Trocando o nome do processo para poolpingPAI
        strncpy(argv[0], "udp_PAI", strlen(argv[0]));
        
        ppid = getpid();
        char settar_cpup[30]; 

        sprintf(settar_cpup, "taskset -cp 4 %d", ppid);
        printf("\n<PID DO PAI %d>\n", ppid);
        printf("%s\nPROCESSO PAI COMECOU O WHILE E NA CPU 4\n", settar_cpup);
        system(settar_cpup);

        fpid = *ptr_trava;

        if( bind(fd_sock_server, (struct sockaddr*)&server_addr, sizeof(server_addr)) ){
            perror("Erro no BIND do PROC_PAI");
            capta_sinal( SIGINT );
        }

        struct sockaddr_in teste;
        socklen_t tam_teste = sizeof(teste);
        int temp = 0;
        // Espera pelo sinal do proc filho
        while(1){
            //printf("PID do filho %d\n", fpid);
            if ( recvfrom(fd_sock_server, MSG_UDP, sizeof(MSG_UDP), 0 , (struct sockaddr *)&server_addr, &server_len) < 0 ){
                perror("<PROC_PAI>Erro ao enviar pkt para filho...");
            }
            xsk_ring_cons__release(&umem_info2->rx, ptr_mem_info_global->ret_ring);
            complete_tx(ptr_mem_info_global->umem_frame_addr, 
                            ptr_mem_info_global->umem_frame_free, 
                            &ptr_mem_info_global->tx_restante);
            //printf("<PROC_PAI>Pai recebeu pkt do filho....\n");
            if ( sendto(fd_sock_server, MSG_UDP, sizeof(MSG_UDP), 0, (struct sockaddr *)&server_addr, server_len) < 0  ){
                perror("<PROC_PAI>Erro ao enviar pkt para filho...");
            }
           
            //if ( recvfrom(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL)  < 0 ) {
            
            //if ( recvfrom(xsk_socket__fd(xsk), NULL, 0, /*MSG_TRUNC 0*/ /*MSG_PEEK*/ 0, NULL, NULL)  < 0 ) {
            //    perror("Erro ao receber syscall do XSK");
            //    continue;
            //}

            //printf("errno--> %d\nrecebeu pkt(%d)\n", errno, temp++);

            //if ( recvfrom(fd_sock_server, MSG_UDP, sizeof(MSG_UDP), 0 , (struct sockaddr *)&server_addr, &server_len) < 0 ){
            //    perror("<PROC_PAI>Erro ao enviar pkt para filho...");
            //}
            //
            //else{
            //    xsk_ring_cons__release(&umem_info2->rx, ptr_mem_info_global->ret_ring);
            //    complete_tx(ptr_mem_info_global->umem_frame_addr, 
            //            ptr_mem_info_global->umem_frame_free, 
            //            &ptr_mem_info_global->tx_restante);
            //    //printf("<PROC_PAI>Pai recebeu pkt do filho....\n");
            //if ( sendto(fd_sock_server, MSG_UDP, sizeof(MSG_UDP), 0, (struct sockaddr *)&server_addr, server_len) < 0  ){
            //    perror("<PROC_PAI>Erro ao enviar pkt para filho...");
            //    }
            //}
            

        }
    }
    else{
        perror("+++ ERRO NO FORK +++");
        capta_sinal(2);
    }
    
    return 0;
}

