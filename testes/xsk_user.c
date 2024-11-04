#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>

//#include <bpf/xsk.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <sys/resource.h>
#include <signal.h>
#include <assert.h>


#define NUM_FRAMES 4096
#define FRAME_SIZE 2048
#define INVALID_UMEM_FRAME UINT64_MAX

struct xdp_program *xdp_prog;
struct bpf_object *bpf_obj;
int ifindex;

int lock = 1;

struct xsk_umem_config umem_cfg = {
    .fill_size = NUM_FRAMES,
    .comp_size = NUM_FRAMES,
    .frame_size = FRAME_SIZE,
    .frame_headroom = 0,
};

/*****************************************/

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_umem_info *umem_info;


/*****************************************/
struct xsk_umem *umem = NULL;
struct xsk_socket *xsk = NULL;

// Config dos ANEIS 
struct xsk_ring_prod fill_ring;
struct xsk_ring_cons comp_ring;
struct xsk_ring_cons rx_ring;
struct xsk_ring_prod tx_ring;

// Configuracoes do socket XSK
struct xsk_socket_config xsk_cfg = {
    .rx_size = NUM_FRAMES,
    .tx_size = NUM_FRAMES,
    //.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    //.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
    //.libbpf_flags = 0,
    .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
    .xdp_flags = XDP_FLAGS_SKB_MODE,
    //.xdp_flags = XDP_FLAGS_DRV_MODE,
};


void *buffer_do_pacote;





/************************************************************************/
static void remove_xdp(){
    //getchar();
	xdp_program__detach(xdp_prog, 2, XDP_MODE_SKB, 0);
	//xdp_program__detach(xdp_prog, 2, XDP_MODE_NATIVE, 0);
	xdp_program__close(xdp_prog);

    printf("\nPrograma Removido!\n");
    lock = 0;

    //return;
	exit(1);
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

static void desaloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free ,uint64_t frame){
	assert(*frame_free < NUM_FRAMES);

	vetor_frame[*frame_free++] = frame;
}
/*************************************************************************/
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    struct xsk_umem_config umem_cfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = 0,
    };



//    struct xsk_umem_info *umem_info;
//
//    struct xsk_umem *umem = NULL;
//    struct xsk_socket *xsk = NULL;
//    struct xsk_ring_prod fill_ring;
//    struct xsk_ring_cons comp_ring;
//    struct xsk_ring_cons rx_ring;
//    struct xsk_ring_prod tx_ring;
//    struct xsk_socket_config xsk_cfg = {
//        .rx_size = NUM_FRAMES,
//        .tx_size = NUM_FRAMES,
//        //.libbpf_flags = 0,
//        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
//        .xdp_flags = XDP_FLAGS_SKB_MODE,
//        //.xdp_flags = XDP_FLAGS_DRV_MODE,
//    };
//    void *buffer_do_pacote;

    char *caminho_prog = "xsk_kern.o";

    signal(SIGINT, remove_xdp);

    /********************************************************************************/
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
	//
	int ret_attach = xdp_program__attach(xdp_prog, ifindex, XDP_MODE_SKB, 0);
	//int ret_attach = xdp_program__attach(xdp_prog, ifindex, XDP_MODE_NATIVE, 0);
	if (ret_attach) {
		printf("Error, Set xdp fd on %d failed\n", ifindex);
		return ret_attach;
	}

	// Find the map fd from the bpf object 
	bpf_obj = xdp_program__bpf_obj(xdp_prog);
	
    //bpf_obj = bpf_object__open_file(caminho_prog, NULL);
    if (bpf_obj == NULL){
        perror("Erro ao abrir o arquivo para bpf_object");
    }
	
    //int mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "mapa_fd");
	int mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xsk_map"); 
	if (mapa_fd < 0) {
		printf("Erro ao tentar obter o fd do mapa pelo bpf_obj, retorno: %d\n", mapa_fd);
        bpf_object__close(bpf_obj);
		return mapa_fd;
	}
 
    // Associa o socket AF_XDP ao mapa XSKMAP
    int map_fd = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(xdp_prog), "xsk_map");
    if (map_fd < 0) {
        fprintf(stderr, "Erro ao encontrar o mapa xsk_map\n");
        xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        xdp_program__close(xdp_prog);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem);
        free(buffer_do_pacote);
        return 1;
    }



    /********************************************************************************/
    // Configuração de limites para aumentar o limite de memória bloqueada
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("Erro ao configurar limite de memória bloqueada");
        return 1;
    }

    // Alocação de memória para o UMEM
    int tam_buffer_pkt = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&buffer_do_pacote, getpagesize(), tam_buffer_pkt)) {
        perror("posix_memalign");
        return 1;
    }

    // Criação do UMEM
    //umem_info = configura_xsk_umem(buffer_do_pacote, tam_buffer_pkt);
    int ret_umem_create;
    umem_info = calloc(1, sizeof(struct xsk_umem_info *)); 

    ret_umem_create = xsk_umem__create(&umem_info->umem, buffer_do_pacote, NUM_FRAMES * FRAME_SIZE, /*&fill_ring*/ &umem_info->fq, /*&comp_ring*/ &umem_info->cq, &umem_cfg);

    //if (xsk_umem__create(&umem, buffer_do_pacote, NUM_FRAMES * FRAME_SIZE, &fill_ring, &comp_ring, &umem_cfg)) {
    if ( ret_umem_create ) {
        fprintf(stderr, "Erro ao criar UMEM: %s\n", strerror(errno));
        free(buffer_do_pacote);
        return 1;
    }

    // Configuração do socket AF_XDP
    //if (xsk_socket__create(&xsk, iface, 0, umem, &rx_ring, &tx_ring, &xsk_cfg)) {
    if (xsk_socket__create(&xsk, iface, 0, umem_info->umem, &rx_ring, &tx_ring, &xsk_cfg)) {
        fprintf(stderr, "Erro ao criar socket XDP: %s\n", strerror(errno));
        xsk_umem__delete(umem);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }


    
    int sock_fd = xsk_socket__fd(xsk);
    int index = 0;
    if (bpf_map_update_elem(map_fd, &index, &sock_fd, BPF_ANY) < 0) {
        
        fprintf(stderr, "Erro ao associar socket ao mapa XSKMAP: %s\n", strerror(errno));
        xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_DRV_MODE, 0);
        
        xdp_program__close(xdp_prog);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }

	int ret = xsk_socket__update_xskmap(xsk, mapa_fd);
	//int ret = xsk_socket__update_xskmap(xsk, map_fd);
    if (ret < 0){
        fprintf(stderr, "Erro ao atualizar o mapa xsk_map\n");
        xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        xdp_program__close(xdp_prog);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }



    printf("\n\nSocket XDP configurado com sucesso na interface %s.\n\n", iface);

    /* ########################################CONFIG DOS ANEIS#################################################### */

    __u32 idx;
   
    uint64_t umem_frame_addr[NUM_FRAMES];

    // Alocando os frames para os buffers
	for (int i = 0; i < NUM_FRAMES; i++)
		umem_frame_addr[i] = i * FRAME_SIZE;

    // Trava para ver se ainda ha espaco para os consumir frames
    uint32_t umem_frame_free = NUM_FRAMES;
    
    // Enchendo o caminho de recebimento com buffers
    // Salva o valor de buffers reservados em idx
    int ret_reserve = xsk_ring_prod__reserve(&umem_info->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    printf("VALOR DO ret_reserve %d\n", ret_reserve);
    
    if( ret_reserve !=  XSK_RING_PROD__DEFAULT_NUM_DESCS){
        printf("Erro ao reservar buffer FILL, ret_reserve != XSK_RING_PROD__DEFAULT_NUM_DESCS\n");
        xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        xdp_program__close(xdp_prog);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }
    
    // Carregando os buffers
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++){
    	*xsk_ring_prod__fill_addr(&umem_info->fq, idx++) = alloca_umem_frame(umem_frame_addr, &umem_frame_free);
        //printf("************ %p\n", xsk_ring_prod__fill_addr(&umem_info->fq, idx));
    }

   	xsk_ring_prod__submit(&umem_info->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    int ret_ring;
    unsigned int stock_frames;
    // Loop para processar pacotes
    while (lock == 1) {
        
        // esse laco pode ser o equivalente a funcao handle_receive_packets
        // do advanced03-AF-XDP
        uint32_t idx_rx = 0;
        uint32_t idx_fq = 0;

        // Verifica se há pacotes no ring buffer de recepção
        // xsk_ring_cons_peek(ANEL_RX, tam_buffer, )
        ret_ring = xsk_ring_cons__peek(&rx_ring, 64, &idx_rx);
        printf("VALOR DO ret_ring %d\n", ret_ring);

        if (ret_ring == 0){
            printf("ret_ring == 0, sem espaco livre, saindo...\n");
            xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
            xdp_program__close(xdp_prog);
            xsk_socket__delete(xsk);
            //xsk_umem__delete(umem);
            xsk_umem__delete(umem_info->umem);
            free(buffer_do_pacote);
            return 1;
        }
        
        if ( ret_ring >= 0){

            stock_frames = xsk_prod_nb_free(&umem_info->fq,	umem_frame_free);
            printf("VALOR DO stock_frames %d\n", stock_frames);

            if(stock_frames > 0){
                printf("stock_frames OK\n");

                int ret_res = xsk_ring_prod__reserve(&umem_info->fq, stock_frames, &idx_fq);
                /* This should not happen, but just in case */
                while (ret_res != stock_frames)
                    ret_res = xsk_ring_prod__reserve(&umem_info->fq, ret_ring, &idx_fq);

                for (int i = 0; i < stock_frames; i++)
                    *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(umem_frame_addr, &umem_frame_free);

                xsk_ring_prod__submit(&umem_info->fq, stock_frames);
            }


            /* Process received packets */
           for (int i = 0; i < ret_ring; i++) {
               uint64_t addr = xsk_ring_cons__rx_desc(&rx_ring, idx_rx)->addr;
               uint32_t len = xsk_ring_cons__rx_desc(&rx_ring, idx_rx++)->len;

               //if (!process_packet(xsk, addr, len))
               //    desaloca_umem_frame(umem_frame_addr, &umem_frame_free, addr);

               //xsk->stats.rx_bytes += len;
           }

           xsk_ring_cons__release(&rx_ring, ret_ring);
           //xsk->stats.rx_packets += ret_ring;


            //const struct xdp_desc *rx_desc;
            //
            //rx_desc =  xsk_ring_cons__rx_desc(&rx_ring, idx_rx);
            //void *pkt_addr = xsk_umem__get_data(buffer_do_pacote, rx_desc->addr);

            //// Processamento do pacote
            //printf("Pacote recebido, tamanho: %u bytes\n", rx_desc->len);

            //// Libera o frame para reutilização
            //xsk_ring_cons__release(&rx_ring, 1);

            //// Envia o frame de volta ao ring buffer de preenchimento
            //if (xsk_ring_prod__reserve(&fill_ring, 1, &idx_rx) == 1) {
            //    *xsk_ring_prod__fill_addr(&fill_ring, idx_rx) = rx_desc->addr;
            //    xsk_ring_prod__submit(&fill_ring, 1);
            //}

        }
        else{
            //printf("CAIU NO ELSE\n");
        }

    }
    
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    free(buffer_do_pacote);
    
    return 0;
}

