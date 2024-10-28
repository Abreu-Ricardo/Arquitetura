#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/xsk.h>
#include <net/if.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/bpf.h>
#include <sys/resource.h>
#include <signal.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE 2048


struct xdp_program *xdp_prog;
struct bpf_object *bpf_obj;
int ifindex;

int lock = 1;

/************************************************************************/
static void remove_xdp(){
    //getchar();
	xdp_program__detach(xdp_prog, 2, XDP_MODE_SKB, 0);
	//xdp_program__detach(xdp_prog, 2, XDP_MODE_NATIVE, 0);
	xdp_program__close(xdp_prog);

    printf("\nPrograma Removido!\n");
    lock = 0;

    return;
	//exit(0);
}
/************************************************************************/


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

    struct xsk_umem *umem = NULL;
    struct xsk_socket *xsk = NULL;
    struct xsk_ring_prod fill_ring;
    struct xsk_ring_cons comp_ring;
    struct xsk_ring_cons rx_ring;
    struct xsk_ring_prod tx_ring;
    struct xsk_socket_config xsk_cfg = {
        .rx_size = NUM_FRAMES,
        .tx_size = NUM_FRAMES,
        //.libbpf_flags = 0,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        //.xdp_flags = XDP_FLAGS_DRV_MODE,
    };
    void *umem_area;

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
        free(umem_area);
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
    if (posix_memalign(&umem_area, getpagesize(), NUM_FRAMES * FRAME_SIZE)) {
        perror("posix_memalign");
        return 1;
    }

    // Criação do UMEM
    if (xsk_umem__create(&umem, umem_area, NUM_FRAMES * FRAME_SIZE, &fill_ring, &comp_ring, &umem_cfg)) {
        fprintf(stderr, "Erro ao criar UMEM: %s\n", strerror(errno));
        free(umem_area);
        return 1;
    }

    // Configuração do socket AF_XDP
    if (xsk_socket__create(&xsk, iface, 0, umem, &rx_ring, &tx_ring, &xsk_cfg)) {
        fprintf(stderr, "Erro ao criar socket XDP: %s\n", strerror(errno));
        xsk_umem__delete(umem);
        free(umem_area);
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
        free(umem_area);
        return 1;
    }

	int ret = xsk_socket__update_xskmap(xsk, map_fd);
    if (ret < 0){
        fprintf(stderr, "Erro ao atualizar o mapa xsk_map\n");
        xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        xdp_program__close(xdp_prog);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem);
        free(umem_area);
        return 1;
    }



    printf("\n\nSocket XDP configurado com sucesso na interface %s.\n", iface);
    
    int ret_ring;

    // Loop para processar pacotes
    while (lock == 1) {
        
        uint32_t idx_rx = 0;

        // Verifica se há pacotes no ring buffer de recepção
        ret_ring = xsk_ring_cons__peek(&rx_ring, 1, &idx_rx);
        if (ret_ring < 0) {
            const struct xdp_desc *rx_desc;
            
            rx_desc =  xsk_ring_cons__rx_desc(&rx_ring, idx_rx);
            void *pkt_addr = xsk_umem__get_data(umem_area, rx_desc->addr);

            // Processamento do pacote
            printf("Pacote recebido, tamanho: %u bytes\n", rx_desc->len);

            // Libera o frame para reutilização
            xsk_ring_cons__release(&rx_ring, 1);

            // Envia o frame de volta ao ring buffer de preenchimento
            if (xsk_ring_prod__reserve(&fill_ring, 1, &idx_rx) == 1) {
                *xsk_ring_prod__fill_addr(&fill_ring, idx_rx) = rx_desc->addr;
                xsk_ring_prod__submit(&fill_ring, 1);
            }
        }
        else{
            //printf("CAIU NO ELSE\n");
        }


       // struct xdp_desc *rx_desc;
       // uint32_t idx_rx = 0;

       // if (xsk_ring_cons__peek(&rx_ring, 1, &idx_rx) != 0) {
       //     rx_desc = xsk_ring_cons__rx_desc(&rx_ring, idx_rx);
       //     void *pkt_addr = xsk_umem__get_data(umem_area, rx_desc->addr);

       //     // Processamento de pacote
       //     printf("Pacote recebido de tamanho: %u bytes\n", rx_desc->len);

       //     xsk_ring_cons__release(&rx_ring, 1);
       // }
    }

    // Limpeza
    //xdp_program__detach(xdp_prog,ifindex, XDP_FLAGS_SKB_MODE, 0);
    //xdp_program__close(xdp_prog);
    
    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    free(umem_area);
    
    return 0;
}

