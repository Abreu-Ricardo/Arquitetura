#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>

//#include <bpf/xsk.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
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

#include <sys/resource.h>
#include <signal.h>
#include <assert.h>

//#include "../bib/teste_bib.h"


#define NUM_FRAMES 4096
//#define NUM_FRAMES 2048
//#define FRAME_SIZE 4096
#define FRAME_SIZE 2048

#define INVALID_UMEM_FRAME UINT64_MAX

struct xdp_program *xdp_prog;
struct bpf_object *bpf_obj;
struct bpf_map *bpf_map;
int ifindex;

int lock = 1;
int cont_regiao = 0;
char *nome_regiao = "/memtest";

//struct info_ebpf bpf;

// Estrutura de dados para configurar o socket xsk
struct xsk_umem_config umem_cfg = {
    .fill_size = NUM_FRAMES,
    .comp_size = NUM_FRAMES,
    .frame_size = FRAME_SIZE,
    .frame_headroom = 0,
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

struct xsk_umem_info *umem_info;


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
};

struct xsk_socket *xsk = NULL;
void *buffer_do_pacote; // e usar o ptr da mem compart do shm()


/************************************************************************/
static void remove_xdp(){
     
    //getchar();
    
    bpf_map__unpin( bpf_object__find_map_by_name(bpf_obj, "mapa_fd") , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_fd");  
    bpf_map__unpin( bpf_object__find_map_by_name(bpf_obj, "xsk_map") , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/xsk_map");

	//xdp_program__detach(xdp_prog, 2, XDP_MODE_SKB, 0);
	xdp_program__detach(xdp_prog, 2, XDP_MODE_NATIVE, 0);
	xdp_program__close(xdp_prog);

    xsk_socket__delete(xsk);
    xsk_umem__delete(umem_info->umem);
    
    // Free a block allocated by \`malloc', \`realloc' or \`calloc'.
    // free(buffer_do_pacote);

    printf("\nPrograma Removido!\n");
    shm_unlink(nome_regiao);

    system("rm /home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/xsk_kern_rodata");
    
    lock = 0;
    //return;
	exit(1);
}
/************************************************************************/

void configura_umem(){
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("Erro ao configurar limite de memória bloqueada");
        exit(1);
    }

    // Alocação de memória para o UMEM
    int tam_buffer_pkt = NUM_FRAMES * FRAME_SIZE;

    /**************************Alocand mem do tutorial*************************************************/
    // Allocate memory of SIZE bytes with an alignment of ALIGNMENT.  
    //if (posix_memalign(&buffer_do_pacote, getpagesize(), tam_buffer_pkt)) {
    //    perror("posix_memalign");
    //    exit(1);
    //}

    // Criação do UMEM, da regiao de mem compart do xsk
    // CRIAR A MINHA PROPRIA COM SHM E FAZER COM QUE ELE USE ESSA MEM PARA
    // ESCREVER E LER OS PACOTES
    //umem_info = configura_xsk_umem(buffer_do_pacote, tam_buffer_pkt);
    
    /***************************************************************************/

    int ret_umem_create;
    umem_info = calloc(1, sizeof(struct xsk_umem_info *)); 

    ret_umem_create = xsk_umem__create(&umem_info->umem, buffer_do_pacote, NUM_FRAMES * FRAME_SIZE, &umem_info->fq, &umem_info->cq, &umem_cfg);
    if ( ret_umem_create < 0 ) {
        fprintf(stderr, "Erro ao criar UMEM: %s\n", strerror(errno));
        free(buffer_do_pacote);
        exit(1);
    }
   return;
}

/************************************************************************/
void configura_socket(const char *iface ){


    // Configuração do socket AF_XDP
    //if (xsk_socket__create(&xsk, iface, 0, umem, &rx_ring, &tx_ring, &xsk_cfg)) {
    if (xsk_socket__create(&xsk, iface, 0, umem_info->umem, &umem_info->rx, &umem_info->tx, &xsk_cfg) < 0) {
        fprintf(stderr, "Erro ao criar socket XDP: %s\n", strerror(errno));
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        exit(1);
    }

    int sock_fd = xsk_socket__fd(xsk);
    int index = 0;
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
static inline __sum16 csum16_add(__sum16 csum, __be16 addend){
	uint16_t res = (uint16_t)csum;

	res += (__u16)addend;
	return (__sum16)(res + (res < (__u16)addend));
}

/****************************************************************************/
static inline __sum16 csum16_sub(__sum16 csum, __be16 addend){
	return csum16_add(csum, ~addend);
}

/****************************************************************************/
static inline void csum_replace2(__sum16 *sum, __be16 old, __be16 new){
	*sum = ~csum16_add(csum16_sub(~(*sum), old), new);
}
/*************************************************************************/
static int processa_pacote(struct xsk_umem_info *umem_info, uint64_t addr, uint32_t len){


    // Allow to get a pointer to the packet data with the Rx descriptor, in aligned mode.
    uint8_t *pkt = xsk_umem__get_data(buffer_do_pacote, addr);
    printf("addr do pkt: %p\n", pkt);

    /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
     *
     * Some assumptions to make it easier:
     * - No VLAN handling
     * - Only if nexthdr is ICMP
     * - Just return all data with MAC/IP swapped, and type set to
     *   ICMPV6_ECHO_REPLY
     * - Recalculate the icmp checksum */

    int ret;
    uint32_t tx_idx = 0;
    uint8_t tmp_mac[ETH_ALEN];
    //struct in6_addr tmp_ip;
    struct in_addr tmp_ip;
    struct ethhdr  *eth = (struct ethhdr *) pkt;
    struct iphdr   *ip  = (struct iphdr  *) (eth + 1);
    //struct ipv6hdr *ipv6 = (struct ipv6hdr *) (eth + 1);
    struct icmphdr *icmph = (struct icmphdr *) (ip + 1);
    //struct icmp6hdr *icmp = (struct icmp6hdr *) (ipv6 + 1);

   // if (ntohs(eth->h_proto) != ETH_P_IPV6 || len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*icmp)) ||
   //         ipv6->nexthdr != IPPROTO_ICMPV6 || icmp->icmp6_type != ICMPV6_ECHO_REQUEST)
   //     return false;
    
    printf("******* icmp->code: %d\n", ntohs(icmph->code));
    if (ntohs(eth->h_proto) != ETH_P_IP || len < (sizeof(*eth) + sizeof(*ip) + sizeof(*icmph)) 
        /*||     icmph->code != ICMP_ECHO*/){
        printf("NAO EH ICMP\n");
        return false;
    }

    printf("\n\n EH ICMP! \n\n");
    
    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    memcpy(&tmp_ip, &ip->saddr, sizeof(tmp_ip));
    memcpy(&ip->saddr, &ip->daddr, sizeof(tmp_ip));
    memcpy(&ip->daddr, &tmp_ip, sizeof(tmp_ip));

    icmph->code = ICMP_ECHOREPLY;
    csum_replace2(&icmph->checksum, htons(ICMP_ECHO << 8), htons(ICMP_ECHOREPLY << 8));

    //memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
    //memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
    //memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));
    //icmp->icmp6_type = ICMPV6_ECHO_REPLY;
    //csum_replace2(&icmp->icmp6_cksum, htons(ICMPV6_ECHO_REQUEST << 8), htons(ICMPV6_ECHO_REPLY << 8));

    /* Here we sent the packet out of the receive port. Note that
     * we allocate one entry and schedule it. Your design would be
     * faster if you do batch processing/transmission */

    // Reserve one or more slots in a producer ring.
    // __u32 number of slots that were successfully reserved (idx) on success, or a 0 in case of failure.
    ret = xsk_ring_prod__reserve(&umem_info->tx, 1, &tx_idx);
    if (ret != 1) {
        /* No more transmit slots, drop the packet */
        return false;
    }

    xsk_ring_prod__tx_desc(&umem_info->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&umem_info->tx, tx_idx)->len = len;
    xsk_ring_prod__submit( &umem_info->tx, 1);
    umem_info->tx_restante++;

    //xsk->stats.tx_bytes += len;
    //xsk->stats.tx_packets++;
    return true;

    
}
/*************************************************************************/
static void complete_tx(uint64_t *vetor_frame, uint32_t *frame_free){
	
    unsigned int completed;
	uint32_t idx_cq;

	if (!umem_info->tx_restante)
		return;

	sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Collect/free completed TX buffers */
	completed = xsk_ring_cons__peek(&umem_info->cq,	XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

	if (completed > 0) {
        //printf("-->Entrou no completed<--\n");
		
        for (int i = 0; i < completed; i++){
            //printf("Desalocando %d\n", i);
			desaloca_umem_frame(vetor_frame, frame_free, *xsk_ring_cons__comp_addr(&umem_info->cq, idx_cq++) );
        }

		xsk_ring_cons__release(&umem_info->cq, completed);
		umem_info->tx_restante -= completed < umem_info->tx_restante ?	completed : umem_info->tx_restante;
	}
    return;
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
    //char *nome_regiao = "/memtest";

    char *ptr_fim_regiao;
    uint64_t  *ptr_regiao;
    
    signal(SIGINT, remove_xdp);

    /***********************************************************************/
    // Carrega e anexa o programa XDP usando libxdp
    ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		printf("Erro ao converter o nome da interface para indice\n");
		return 1;
	}

    printf("Indice da interface %d\n",ifindex);
	// load XDP object by libxdp 
	xdp_prog = xdp_program__open_file(caminho_prog, "xdp", NULL);
	if (!xdp_prog) {
		printf("Erro ao abrir o programa xdp\n");
		return 1;
	}

	// attach XDP program to interface with xdp mode
	// Please set ulimit if you got an -EPERM error.
	//int ret_attach = xdp_program__attach(xdp_prog, ifindex, XDP_MODE_SKB, 0);
	int ret_attach = xdp_program__attach(xdp_prog, ifindex, XDP_MODE_NATIVE, 0);
	if (ret_attach) {
		printf("Error, Set xdp fd on %d failed\n", ifindex);
		return ret_attach;
	}

	// Find the map fd from the bpf object
    // Pega um bpf_object a partir da struct xdp_program
	bpf_obj = xdp_program__bpf_obj(xdp_prog);
	
    //bpf_obj = bpf_object__open_file(caminho_prog, NULL);
    if (bpf_obj == NULL){
        perror("Erro ao abrir o arquivo para bpf_object");
    }
	
    //int mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "mapa_fd");
    // Pega o fd do mapa
	int mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xsk_map"); 
	if (mapa_fd < 0) {
		printf("Erro ao tentar obter o fd do mapa pelo bpf_obj, retorno: %d\n", mapa_fd);
        bpf_object__close(bpf_obj);
		return mapa_fd;
	}
 
    int map_fd_xsk = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(xdp_prog), "xsk_map");
    if (map_fd_xsk < 0) {
        fprintf(stderr, "Erro ao encontrar o mapa xsk_map\n");
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_DRV_MODE, 0);
        xdp_program__close(xdp_prog);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }

    bpf_object__pin_maps(bpf_obj, "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados");
    //int fd_mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "mapa_fd");
    int fd_mapa_fd = bpf_obj_get("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_fd"); 
    int chave =0, valor;
    
    bpf_map = bpf_object__find_map_by_name(bpf_obj, "xsk_map");
    int retorno = bpf_map_update_elem(fd_mapa_fd, &chave, &nome_regiao, BPF_ANY );

    printf("\nfd do mapa xsk: %d\n", map_fd_xsk);
    printf("-->fd do fd_mapa_fd: %d\n", fd_mapa_fd);

    /**************************************************************************************************************/

    //char *caminho_prog = "xsk_kern.o";
    //char *nome_regiao = "/memtest";
    
    //carrega_ebpf(caminho_prog, "teste", &bpf);
    //atualiza_mapa(caminho_prog, "mapa_fd", nome_regiao, &bpf);
    //le_mapa(&bpf);

    //int fd_shm = shm_open(nome_regiao, O_CREAT | O_RDWR, 0666);
    
    int fd_shm = shm_open(nome_regiao, O_CREAT | O_RDWR, 0777);
    if (fd_shm == -1){
        perror("Erro em shm_open\n");
        exit(1);
    }

    uint64_t vetor_dados[100];
    // Tamanho da regiao de mem.
    //int tam_regiao = 500 * sizeof( vetor_dados ) + 1;
    int tam_regiao = NUM_FRAMES * FRAME_SIZE;
    
        // Atribuindo tamanho para a regiao de mem. compart.
    int ret_ftruncate = ftruncate(fd_shm, tam_regiao);
    if ( ret_ftruncate == -1 ){
        perror("Erro em ftruncate\n");
        exit(1);
    }
    
    buffer_do_pacote   = ( void *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);

    ptr_regiao         = (uint64_t  *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    ptr_fim_regiao     = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    //ptr_fim_regiao += tam_regiao - 1;

    /**************************************************************************************************************/
   
    /*###############################FIM DO CARREGAMENTO DO PROGRAMA###################################################*/
    
    configura_umem();
    configura_socket( iface);

    /*###############################FIM CONFIGS DA UMEM E SOCKET###################################################*/

    // Atualiza o mapa xsk com valor do fd do socket criado
	int ret = xsk_socket__update_xskmap(xsk, map_fd_xsk);
    if (ret < 0){
        fprintf(stderr, "Erro ao atualizar o mapa xsk_map\n");
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_DRV_MODE, 0);
        xdp_program__close(xdp_prog);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }

    int key = 0;
    char *ret_lookup = "valor inicial"; // valor para ver se escreveu algo na var
    int ret_look;
    ret_look = bpf_map_lookup_elem(fd_mapa_fd, &key, &ret_lookup);
    
    if(ret_look < 0){
        printf("DEU ERRADO OLHAR O MAPA: %d\n", ret_look);
    }

    printf("\nValor do retorno do mapa: %s\n\n", ret_lookup);
    printf("\n\nSocket XDP configurado com sucesso na interface %s.\n\n", iface);

    /**************************************************************************************************************/



    /* ########################################CONFIG DOS ANEIS#################################################### */

    __u32 idx;
   
    uint64_t umem_frame_addr[NUM_FRAMES];

    // Alocando os frames para os buffers
	for (int i = 0; i < NUM_FRAMES; i++){
		umem_frame_addr[i] = i * FRAME_SIZE;
    }

    // Trava para ver se ainda ha espaco para os consumir frames
    uint32_t umem_frame_free = NUM_FRAMES;
    
    // Enchendo o caminho de recebimento com buffers
    // Salva o valor de buffers reservados em idx
    int ret_reserve = xsk_ring_prod__reserve(&umem_info->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    printf("VALOR DO ret_reserve %d valor do idx:%d\n", ret_reserve, idx);
    
    if( ret_reserve !=  XSK_RING_PROD__DEFAULT_NUM_DESCS){
        printf("Erro ao reservar buffer FILL, ret_reserve != XSK_RING_PROD__DEFAULT_NUM_DESCS\n");
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_DRV_MODE, 0);
        xdp_program__close(xdp_prog);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }
    
    // Carregando os buffers
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++){
        //printf("i:%d ************ %p\n", i, xsk_ring_prod__fill_addr(&umem_info->fq, idx));

    	//xsk_ring_prod__fill_addr() --> Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
        //retorna o endereco do pacote
        *xsk_ring_prod__fill_addr(&umem_info->fq, idx++) = alloca_umem_frame(umem_frame_addr, &umem_frame_free);
    }

    // xsk_ring_prod__submit() --> Submit the filled slots so the kernel can process them.
   	xsk_ring_prod__submit(&umem_info->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    int ret_ring;
    unsigned int stock_frames;

    // ############################## PROCESSAMENTO DOS PACOTE #############################
    // Loop para processar pacotes
    while (lock == 1) {
        
        // esse laco pode ser o equivalente a funcao handle_receive_packets
        // do advanced03-AF-XDP
        uint32_t idx_rx = 0;
        uint32_t idx_fq = 0;

        // Verifica se há pacotes no ring buffer de recepção
        // xsk_ring_cons_peek(ANEL_RX, tam_do_lote, )
        // Essa funcao no exemplo advanced03 tbm retorna 0
        ret_ring = xsk_ring_cons__peek(&umem_info->rx, 64, &idx_rx);
 
        //printf("\nVALOR DO ret_ring %d\n", ret_ring);
        //printf("valor do umem_frame_free: %d\n",umem_frame_free);

        if( !ret_ring ){
            //printf("\n\n <ret_ring deu zero>\n");
            continue;
       }

        // Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
        // retorna o endereco do pacote --> __u64 address of the packet.
        stock_frames = xsk_prod_nb_free(&umem_info->fq,	umem_frame_free);
        //printf("******************VALOR DO stock_frames %d\n", stock_frames);

        if(stock_frames > 0){
            printf("stock_frames OK\n");

            // Reserve one or more slots in a producer ring.
            // retorna --> __u32 number of slots that were successfully reserved (idx) on success, or a 0 in case of failure.
            int ret_res = xsk_ring_prod__reserve(&umem_info->fq, stock_frames, &idx_fq);
            
            /* This should not happen, but just in case */
            while (ret_res != stock_frames)
                ret_res = xsk_ring_prod__reserve(&umem_info->fq, ret_ring, &idx_fq);

            for (int i = 0; i < stock_frames; i++){
             //Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
                *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(umem_frame_addr, &umem_frame_free);
            }

            // Submit the filled slots so the kernel can process them
            xsk_ring_prod__submit(&umem_info->fq, stock_frames);
        }

        /* Process received packets */
        for (int i = 0; i < ret_ring; i++) {

            // xsk_ring_cons__rx_desc() --> This function is used to retrieve the receive descriptor at a specific index in the Rx ring
            uint64_t addr = xsk_ring_cons__rx_desc(&umem_info->rx, idx_rx)->addr;
            uint32_t len  = xsk_ring_cons__rx_desc(&umem_info->rx, idx_rx)->len;

            // Escreve na regiao compart
            if (cont_regiao < 100){
                //memcpy(ptr_regiao, &len, sizeof( uint32_t ) );
                //ptr_regiao = ptr_regiao + sizeof(uint64_t *);
                
                cont_regiao++;
                printf("Tamanho do pacote recebido %d | num pkt:%d\n", len, cont_regiao);
            }

            if (processa_pacote(umem_info, addr, len)){
                desaloca_umem_frame(umem_frame_addr, &umem_frame_free, addr);
                //xsk->stats.rx_bytes += len;
            }
        }

        xsk_ring_cons__release(&umem_info->rx, ret_ring);
        
        uint32_t idx_cq;    

        // Check for new packets in the ring and returns __u32 he number of packets that are available in the consumer ring (idx)
        unsigned int completed = xsk_ring_cons__peek(&umem_info->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);
       
        if (completed > 0) {
        	for (int i = 0; i < completed; i++){
                //xsk_ring_cons__comp_addr() --> This function is to read the address of a specific entry in the consumer ring.
                desaloca_umem_frame(umem_frame_addr, &umem_frame_free, *xsk_ring_cons__comp_addr(&umem_info->cq, idx_cq++) );
            }  
            // This function releases a specified number of packets that have been processed from the consumer ring back to the kernel. 
            // Indicates to the kernel that these packets have been consumed and the buffers can be reused for new incoming packets.
            xsk_ring_cons__release(&umem_info->cq, completed);
        }
        complete_tx(umem_frame_addr, &umem_frame_free);
    }
    
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem_info->umem);
    //free(buffer_do_pacote);
    
    return 0;
}

