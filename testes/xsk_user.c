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
#include <linux/bpf.h>
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
	void *buffer;
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
void *buffer_do_pacote; // Trocar esse buffer que eh usado para criar a UMEM
                        // e usar o ptr da mem compart do shm()



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

    // Allocate memory of SIZE bytes with an alignment of ALIGNMENT.  
    //if (posix_memalign(&buffer_do_pacote, getpagesize(), tam_buffer_pkt)) {
    //    perror("posix_memalign");
    //    exit(1);
    //}

    // Criação do UMEM, da regiao de mem compart do xsk
    // CRIAR A MINHA PROPRIA COM SHM E FAZER COM QUE ELE USE ESSA MEM PARA
    // ESCREVER E LER OS PACOTES
    //umem_info = configura_xsk_umem(buffer_do_pacote, tam_buffer_pkt);
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
/*************************************************************************/

static int processa_pacote(struct xsk_umem_info *umem_info, uint64_t addr, uint32_t len){
                   
                   // Allow to get a pointer to the packet data with the Rx descriptor, in aligned mode.
                   // nao retorna nada
    uint8_t *pkt = xsk_umem__get_data(umem_info->buffer, addr);
    return 1;
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
    
    int chave_mapa_fd = 0;
    buffer_do_pacote   = ( void *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    ptr_regiao      = (uint64_t  *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    ptr_fim_regiao  = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
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

    	//xsk_ring_prod__fill_addr --> Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
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
        // retorna --> __u64 address of the packet.
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

            for (int i = 0; i < stock_frames; i++)
                *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(umem_frame_addr, &umem_frame_free);

            // Submit the filled slots so the kernel can process them
            xsk_ring_prod__submit(&umem_info->fq, stock_frames);
        }

        /* Process received packets */
        for (int i = 0; i < ret_ring; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&umem_info->rx, idx_rx)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&umem_info->rx, idx_rx++)->len;

            if (cont_regiao < 100){
                memcpy(ptr_regiao, &len, sizeof( int ) );
                ptr_regiao = ptr_regiao + sizeof(uint64_t *);
                
                cont_regiao++;
                printf("Tamanho do pacote recebido %d | num pkt:%d\n", len, cont_regiao);
            }

            //if (processa_pacote(umem_info, addr, len) == 1){
            //    desaloca_umem_frame(umem_frame_addr, &umem_frame_free, addr);
            //    //xsk->stats.rx_bytes += len;
            //}
        }

        xsk_ring_cons__release(&umem_info->rx, ret_ring);
        
        uint32_t idx_cq;
        unsigned int completed = xsk_ring_cons__peek(&umem_info->cq, XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);
       	if (completed > 0) {
        	for (int i = 0; i < completed; i++){
		                                                                //This function is to read the address of a specific entry in the consumer ring.
                desaloca_umem_frame(umem_frame_addr, &umem_frame_free, *xsk_ring_cons__comp_addr(&umem_info->cq, idx_cq++) );
            }
		   
            // This function releases a specified number of packets that have been processed from the consumer ring back to the kernel. 
            // Indicates to the kernel that these packets have been consumed and the buffers can be reused for new incoming packets.
            xsk_ring_cons__release(&umem_info->cq, completed);
        }
    }
    
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem_info->umem);
    free(buffer_do_pacote);
    
    return 0;
}

