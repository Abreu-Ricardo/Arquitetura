#include "commons.h"

struct xsk_kern_bpf    *skel;
int sockfd_udp;

int  *ptr_trava;
char *nome_regiao      = "/xdp_umem";
char *nome_trava       = "/sock_info";
char *veth2            = "veth2";
char *veth4            = "veth4";
char *nome_info_global = "info_global";

char  nomeproc[30];

pid_t fpid, ppid, pid_alvo;
int fd_sock_client, flag_sockXDP = -1;

struct xsk_socket      *xsk;
struct xsk_socket      *xsk2;
struct xdp_program     *xdp_prog;

struct bpf_object      *bpf_obj;
struct bpf_map         *bpf_map;

struct xsk_kern_bpf    *skel;
struct xsk_umem_info   *umem_info;    // xsk  -- Processo
struct xsk_umem_info   *umem_info2;   // xsk2 -- Processo
struct xsk_info_global *ptr_mem_info_global;
struct sock_info *sock_udp;

struct sockaddr_in client_addr;
socklen_t client_len = sizeof(client_addr);

void *buffer_do_pacote; // e usar o ptr da mem compart do shm()

__u32 ret_ring=0, stock_frames=0;
__uint64_t cont_pkt=0;
uint32_t idx_rx = 0;
uint32_t idx_fq = 0;
uint64_t addr;
uint32_t len; 


/************************************************************************/
static __always_inline volatile long long RDTSC(){

    //register long long TSC asm("eax");
    //asm volatile (".byte 15, 49" : : : "eax", "edx");
    //return TSC;

    unsigned int lo, hi;

    asm ("rdtsc" : "=a" (lo), "=d" (hi)); // Execute RDTSC and store results
    return ((long long)hi << 32) | lo;    // Combine high and low parts
}  

/************************************************************************/
void capta_sinal(int signum){
    //getchar();

    if (signum == 2){

        bpf_map__unpin( bpf_object__find_map_by_name( skel->obj , "mapa_fd")         , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_fd");  
        
        bpf_map__unpin( bpf_object__find_map_by_name( skel->obj , "xsk_map")         , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/xsk_map");
        
        //bpf_map__unpin( bpf_object__find_map_by_name( skel->obj , "xsk_kern_rodata") , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/xsk_kern_rodata");
        
        //bpf_map__unpin( bpf_object__find_map_by_name( skel->obj , "xsk_kern_bss")    , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/xsk_kern_bss");
        
        bpf_map__unpin( bpf_object__find_map_by_name( skel->obj , "tempo_sig")       , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/tempo_sig");
        
        bpf_map__unpin( bpf_object__find_map_by_name( skel->obj , "mapa_sinal")      , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_sinal");

        //xdp_program__detach(xdp_prog, 2, XDP_MODE_SKB, 0);
        //xdp_program__detach(xdp_prog, 2, XDP_MODE_NATIVE, 0);
        //xdp_program__close(xdp_prog);

        xsk_kern_bpf__destroy(skel);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);

        //free(ptr_trava);
        //free(ptr_mem_info_global);
        //free(buffer_do_pacote);
        
        // Free a block allocated by \`malloc', \`realloc' or \`calloc'.
        // free(buffer_do_pacote);

        printf("\nPrograma Removido!\n");
        shm_unlink(nome_regiao);
        shm_unlink(nome_trava);
        shm_unlink(nome_info_global );
        //free(buffer_do_pacote);
       
        system("xdp-loader unload veth2 --all");
        system("xdp-loader status");
        system("rm /home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/xsk_kern_*");
       
        char cmdkill[50];
        sprintf(cmdkill, "killall %s*", nomeproc);
        //system("killall pollping_ref");
        system(cmdkill);
        //kill(fpid, SIGKILL);
        raise(SIGKILL);
        
        lock = 0;
	    exit(0);
    }
    else if (signum == SIGUSR2){
            recebe_RX(ptr_mem_info_global);
        }

    //else if( signum == 10){
    //    recebe_RX( ptr_mem_info_global );
    //}
    //return;
}


/************************************************************************/
void configura_umem(){

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r) < 0) {
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
        //fprintf(stderr, "Erro ao criar UMEM: %s\n", strerror(errno));
        perror("Erro ao criar UMEM");
        capta_sinal(SIGINT);
        //free(buffer_do_pacote);
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
        //xsk_umem__delete(umem_info->umem);
        //free(buffer_do_pacote);
        capta_sinal(SIGINT);
        exit(1);
    }
    
    sock_fd = xsk_socket__fd(xsk);
    index = 0;
    printf("\nValor do fd do socket xsk: %d\n\n", sock_fd);

    if (sock_fd < 0){
        fprintf(stderr, "Erro ao pegar o fd do socket xsk\n");
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_SKB_MODE, 0);
        //xdp_program__detach(xdp_prog, ifindex, XDP_FLAGS_DRV_MODE, 0);
        //xdp_program__close(xdp_prog);
        //xsk_socket__delete(xsk);
        //xsk_umem__delete(umem_info->umem);
        capta_sinal(SIGINT);
        //free(buffer_do_pacote);
        exit(1); 
    }

    int map_fd_xsk = bpf_object__find_map_fd_by_name( skel->obj , "xsk_map");

    // Na implementacao eh usado um bpf_map_update_elem mas na chave eh 
    // usado o id da fila(queue_id), por isso que qnd eu tento fazer na mao da erro
    // socket que eh utilizado eh o xsk2, por isso o pkt eh redirecionado para o
    // socket xsk2
    
    // Se flag_sockXDP == 1 eh preciso atualizar o mapa xskmap com o FD do socket
    if (flag_sockXDP == 1){
        int ret_update = xsk_socket__update_xskmap(xsk, map_fd_xsk);
        if (ret_update < 0){
            fprintf(stderr, "Erro ao atualizar o mapa xsk_map\n");
            capta_sinal(SIGINT);
            free(buffer_do_pacote);
        }
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
        capta_sinal(SIGINT);
		return;
    }
    /*******************/

    // Cria socket compartilhado
    ret = xsk_socket__create_shared(&xsk2, iface, 0, umem_info->umem, &umem_info2->rx, &umem_info2->tx, &umem_info->fq, &umem_info->cq, &xsk_cfg2);
    if (ret < 0) {
        printf("Valor do ret de socket_shared: %d\n", ret);
        fprintf(stderr, "Erro ao criar socket XDP: %s\n", strerror(errno));
        //xsk_umem__delete(umem_info->umem);
        //free(buffer_do_pacote);
        capta_sinal(SIGINT);
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
        //xsk_kern_bpf__destroy(skel);
        //xsk_socket__delete(xsk);
        //xsk_umem__delete(umem_info->umem);
        capta_sinal(SIGINT);
        free(buffer_do_pacote);
    }

    int sock_fd2 = xsk_socket__fd(xsk2);
    printf("Valor do fd do segundo socket: %d\n", sock_fd2);
}


/************************************************************************/
//uint64_t alloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free){
//    
//    uint64_t frame;
//    //if(frame_free == 0)
//    if( ptr_mem_info_global->umem_frame_free == 0 ){
//        //printf("\n(alloca_umem_frame)+++ umem_frame_free deu 0 em alloca_umem_frame() | umem_frame_free: %d +++\n", ptr_mem_info_global->umem_frame_free);
//        //exit(-1);
//        return INVALID_UMEM_FRAME;
//    }
//
//   
//    //printf("\n1(alloca_umem)#### umem_frame_free: %d | frame: %lu\n", ptr_mem_info_global->umem_frame_free, frame);
//    //frame = ptr_mem_info_global->umem_frame_addr[ --ptr_mem_info_global->umem_frame_free ];
//    //uint64_t temp = ptr_mem_info_global->umem_frame_free - 1;
//    //ptr_mem_info_global->umem_frame_free -= 1;
//    
//    frame = ptr_mem_info_global->umem_frame_addr[ --ptr_mem_info_global->umem_frame_free ];
//    ptr_mem_info_global->umem_frame_addr[ptr_mem_info_global->umem_frame_free] = INVALID_UMEM_FRAME;
//
//    //printf("2(alloca_umem)#### umem_frame_free: %d | frame: %lu | posi atual: %lu\n", ptr_mem_info_global->umem_frame_free, frame,
//    //                                                                                ptr_mem_info_global->umem_frame_addr[ptr_mem_info_global->umem_frame_free]);
//    //printf("(alloca_umem)#### frame: %lu\n", frame);
//	//frame = vetor_frame[--*frame_free];
//	//vetor_frame[*frame_free] = INVALID_UMEM_FRAME;
//
//    return frame;
//}

/****************************************************************************/
static __always_inline void desaloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free, uint64_t frame){
	
    //printf("(1desaloca_umem)#### umem_frame_free: %d | frame: %ld\n", ptr_mem_info_global->umem_frame_free, frame);
    assert( ptr_mem_info_global->umem_frame_free < NUM_FRAMES);

   
    ptr_mem_info_global->umem_frame_addr[ ptr_mem_info_global->umem_frame_free++ ] = frame;

    //ptr_mem_info_global->umem_frame_free += 1;
   // printf("(2desaloca_umem)#### umem_frame_free: %d | frame: %ld\n", ptr_mem_info_global->umem_frame_free, frame);
    //printf("(desaloca_umem)#### umem_frame_free: %ld | frame: %ld\n", ptr_mem_info_global->umem_frame_addr[ptr_mem_info_global->umem_frame_free], frame);
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
static __always_inline void csum_replace2(__sum16 *sum, __be16 old, __be16 novo){
	*sum = ~csum16_add(csum16_sub(~(*sum), old), novo);
}
/*************************************************************************/


static __always_inline int processa_pacote(uint64_t addr, uint32_t len){
    // Allow to get a pointer to the packet data with the Rx descriptor, in aligned mode.
  
    /******************************************************/
    //start = RDTSC();
    // Primeiro pacote demora uns 5K ciclos, dai pra frente demora 10-20 ciclos
    uint8_t *pkt = xsk_umem__get_data(buffer_do_pacote, addr);
    //end = RDTSC();
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

       
    // Primeiro pkt demora 3K ciclos, dai pra frente menos de 300 ciclos
    //start = RDTSC();
    /******************************************************/
    ret = xsk_ring_prod__reserve(&umem_info2->tx, 1, &tx_idx);
    if (ret != 1) {
        /* No more transmit slots, drop the packet */
        return false;
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
/*static __always_inline */void complete_tx(uint64_t *vetor_frame, uint32_t *frame_free, uint32_t *tx_restante){
//void complete_tx(/*uint64_t *vetor_frame, uint32_t *frame_free, uint32_t *tx_restante*/){
    //printf("\nENTROU NO complete_tx\n");
    //printf("chamando complete_tx: %d\n", cont);
    //cont++;
    
    //start = RDTSC();

    int i, retsend; 
    unsigned int completed;
	uint32_t idx_cq;
	
    //if (!*tx_restante){
    if (!ptr_mem_info_global->tx_restante){
	    //printf("\n\n###(complete_tx) nao enviou o pkt, umem_info->tx_restante: %d\n", *tx_restante);
        return;
    }

    //printf("\n\nPassou do !umem_info->tx_restante, valor: %d\n", umem_info->tx_restante); 
    
    //sendto() --> Demora mais q tudo nessa func, 18000 ciclos
    retsend = sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    //retsend = sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
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
                //printf("(complete_tx) chamando desaloca_umem_frame | umem_frame_free %d\n", ptr_mem_info_global->umem_frame_free);
                //desaloca_umem_frame(vetor_frame, frame_free, *xsk_ring_cons__comp_addr(&umem_info->cq, idx_cq++) );
                desaloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free, *xsk_ring_cons__comp_addr(&umem_info->cq, idx_cq++) );
            }
            xsk_ring_cons__release(&umem_info->cq, completed);
            //*tx_restante -= completed < *tx_restante ?	completed : *tx_restante;
            ptr_mem_info_global->tx_restante -= completed < ptr_mem_info_global->tx_restante ?	completed : ptr_mem_info_global->tx_restante;
            //printf("Finalizou complete_tx()\n");
        }
    }
    //else{
    //     printf("ERRO, retorno do sendto() menor que 0, valor: %d\n\n", retsend);
    //     printf("*****************************\n\n");
    //}

    //end = RDTSC();
    
    //printf("tempo fil da func complete_tx() --> %f\n", (end - start) / 3.6 );
    //printf("----- Terminou complete_tx() ------\n");
    return;
}
/*************************************************************************/
int tcon = 0;
void complete_tx2(uint64_t *vetor_frame, uint32_t *frame_free, uint32_t *tx_restante){
    //printf("chamando complete_tx2: %d | fd sockUDP: %d\n", tcon++, sock_udp->sockUDP);
    
    //start = RDTSC();
    int i, retsend; 
    unsigned int completed;
	uint32_t idx_cq;

    if (!ptr_mem_info_global->tx_restante){
	    //printf("\n\n###(complete_tx) nao enviou o pkt, umem_info->tx_restante: %d\n", *tx_restante);
        return;
    }

    //printf("\n\nPassou do !umem_info->tx_restante, valor: %d\n", umem_info->tx_restante); 
    
    //sendto() --> Demora mais q tudo nessa func, 18000 ciclos
    //retsend = sendto(xsk_socket__fd(xsk2), NULL, 0, MSG_DONTWAIT, NULL, 0);
    //sendto(sock, buffer, buflen, 0, (struct sockaddr*)dest, sizeof(*dest));

    retsend = sendto(sock_udp->sockUDP, sock_udp->pkt, sock_udp->tam_pkt, 0, (struct sockaddr *)&sock_udp->sa, sizeof(sock_udp->sa));
    
    //printf("--> fd sock:%d tam_pkt:%ld sa:%u %d\n\n", sock_udp->sockUDP, sock_udp->tam_pkt , 
    //        *sock_udp->sa.sll_addr, *sock_udp->pkt);
    //printf("(complete_tx2:)Retorno do sendto: %d | tam_pkt: %ld\n", retsend, sock_udp->tam_pkt);
    if(retsend < 0) perror("Retsend < 0");

    // Se retorno de sendto for < 0, houve erro 
    //if (retsend >= 0){

        //printf("ret sendto: %d\n", retsend);
        /* Collect/free completed TX buffers */

        // Tem hora que leva 40 ciclos outras 1000+
        completed = xsk_ring_cons__peek(&umem_info->cq,	XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);
        uint64_t temp;       
        //printf("(complete_tx2) valor de completed: %d\n", completed);
        if (completed > 0) {
            for (i = 0; i < completed; i++){
                ///*uint64_t*/ temp = *xsk_ring_cons__comp_addr(&umem_info->cq, idx_cq++); 
                desaloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free,  *xsk_ring_cons__comp_addr(&umem_info->cq, idx_cq++) /*temp*/ );
            }
            xsk_ring_cons__release(&umem_info->cq, completed);
            ptr_mem_info_global->tx_restante -= completed < ptr_mem_info_global->tx_restante ?	completed : ptr_mem_info_global->tx_restante;
        //}
    }
    //end = RDTSC();
    return;
}

/*************************************************************************/
// info_global == ptr_mem_info_global
void recebe_RX(struct xsk_info_global *info_global){
    //pid_t tid = pthread_self();
    //printf("<Entrou recebe_RX com a thread:%ld>\n", /*gettid()*/ syscall(SYS_gettid));
    //printf("<Entrou em recebe_RX>\n");
    
    /**************************************************************/
    int i =0;

    __u32 ret_ring=0, stock_frames=0;
    __uint64_t cont_pkt=0;
   
    uint32_t idx_rx = 0;
    uint32_t idx_fq = 0;
    uint64_t addr;
    uint32_t len; 

    while(1){
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
                //raise(SIGUSR2);
                //printf("\n\n <ret_ring deu zero>\n");
                continue;
            }

            ptr_mem_info_global->ret_ring = ret_ring;

            // Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
            // retorna o endereco do pacote --> __u64 address of the packet.
            //stock_frames = xsk_prod_nb_free(&umem_info->fq,	*info_global->umem_frame_free);
            stock_frames = xsk_prod_nb_free(&umem_info->fq,	ptr_mem_info_global->umem_frame_free);
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
                    //*xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(info_global->umem_frame_addr, info_global->umem_frame_free);
                    *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free);
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
                    //desaloca_umem_frame(info_global->umem_frame_addr, info_global->umem_frame_free, addr);
                    desaloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free, addr);
                }
             }


            /*********************/
            *ptr_trava = 1;

           // } 
        }
}

/*************************************************************************/

int i =0;
//__u32       ret_ring=0, stock_frames=0;
//__uint64_t  cont_pkt=0;
//uint32_t    idx_rx = 0;
//uint32_t    idx_fq = 0;
//uint64_t    addr;
//uint32_t    len; 

union sigval valor_struct;
sigset_t set;
//valor.sival_int = dado;  // Anexa dado ao sinal

void recebe_signal_RX(struct xsk_info_global *info_global ){
    //printf("<Entrou em polling_RX>\n");

    //struct sigaction act = {0};
    //act.sa_flags = SA_SIGINFO;  // Permite recebimento de sinal com dados
    //act.sa_sigaction = tempo_sinal;
    //sigemptyset(&act.sa_mask);

    //if (sigaction(SIGUSR1, &act, NULL) == -1) {
    //    perror("sigaction");
    //    capta_sinal(SIGINT);
    //}
    ret_ring = 0, stock_frames=0;   
    cont_pkt = 0;
    idx_rx   = 0;
    idx_fq   = 0;
    addr     = 0;
    len      = 0; 
    /**************************************************************/

    pid_alvo = ppid;


    //while(1){
    //while( sigwait(&set, &sig_usr1) == 0 ){
    while( sigwait(&set, &sigrtmin1) == 0 ){
        //while( pause()  ){
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
                //raise( SIGUSR2 );
                //printf("\n\n<PROC_FILHO> ret_ring deu zero\n");
                //sigwait( &set , &sig );
                continue;
            }

            ptr_mem_info_global->ret_ring = ret_ring;

            // Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
            // retorna o endereco do pacote --> __u64 address of the packet.
            stock_frames = xsk_prod_nb_free(&umem_info->fq,	ptr_mem_info_global->umem_frame_free);
            //printf("******************VALOR DO stock_frames %d\n", stock_frames);

            if(stock_frames > 0){
                //printf("stock_frames OK ret_ring %d\n", ret_ring);
                // Reserve one or more slots in a producer ring.
                // retorna --> __u32 number of slots that were successfully reserved (idx) on success, or a 0 in case of failure.
                int ret_res = xsk_ring_prod__reserve(&umem_info->fq, stock_frames, &idx_fq);

                /* This should not happen, but just in case */
               //	while (ret_res != stock_frames)
               //     ret_res = xsk_ring_prod__reserve(&umem_info->fq, ret_ring, &idx_fq);

                for (i = 0; i < stock_frames; i++){
                    //Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
                    *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free);
                }
                // Submit the filled slots so the kernel can process them
                xsk_ring_prod__submit(&umem_info->fq, stock_frames);
            }


            /* Process received packets */
            for (i = 0; i < ret_ring; i++) {
                // xsk_ring_cons__rx_desc() --> This function is used to retrieve the receive descriptor at a specific index in the Rx ring
                addr = xsk_ring_cons__rx_desc(&umem_info2->rx, idx_rx)->addr;
                len  = xsk_ring_cons__rx_desc(&umem_info2->rx, idx_rx++)->len;

                //printf("Tamanho do pacote recebido %d | num pkt:%ld\n", len, cont_pkt);

                // CHAMA PROCESSA_PACOTE
                //if (!processa_pacote(umem_info,  addr, len)){
                if ( !processa_pacote( addr, len) ){
                    desaloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free, addr);
                }

                cont_pkt++;
             }

            //union sigval valor;
            //valor.sival_int = dado;  // Anexa dado ao sinal

            // Enviando sinal e verificando se deu erro
            //if ( kill(pid_alvo, SIGUSR1) == -1 ) {
            //if ( sigqueue(pid_alvo, SIGUSR1, valor_struct) == -1 ) {
            if ( sigqueue(pid_alvo, SIGRTMIN+1, valor_struct) == -1 ) {
                perror("Erro no sigqueue do filho");
                capta_sinal(SIGINT);
            }
            
            //printf("\n\npkt = %lu\n\n", cont_pkt );
            // Se bateu o limite de pkts a serem processados
            // termina o processo de maneira graciosa para o
            // gprof rodar sem problemas e salvar os dados de profiling
            if ( cont_pkt >= PKT_LIMIT ){
                //kill(pid_alvo, SIGUSR1);
                //kill(pid_alvo, SIGUSR2);
                kill(pid_alvo, SIGRTMIN+1);
                capta_sinal(SIGINT);
            }
        }
}

/*************************************************************************/
char *MSG_UDP = "PODE IR";

void recebe_pkt_RX(struct xsk_info_global *info_global ){
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
    //while( sigwait(&set, &sig_usr1) == 0 ){
    
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

            ptr_mem_info_global->ret_ring = ret_ring;

            // Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
            // retorna o endereco do pacote --> __u64 address of the packet.
            stock_frames = xsk_prod_nb_free(&umem_info->fq,	ptr_mem_info_global->umem_frame_free);
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
                    *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free);
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
                    //desaloca_umem_frame(info_global->umem_frame_addr, info_global->umem_frame_free, addr);
                    desaloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free, addr);
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
                    //printf("<PROC_FILHO>Pkt do PAI recebido...<--\n\n");
                    continue;
                }

            } 
        }
}

/*************************************************************************/

//void signal_handler(int signum, siginfo_t *info, void *context) {
//    if (signum == SIGUSR1) {
//
//        printf("CPU: %d | PID:<%d> Sinal recebido do PROC_FILHO: = %lld \n\n", sched_getcpu() , getpid(), info->si_int + (long long int) + 0 );
// 
//        //printf("\n          ### Sinal recebido SIGUSR1 com dado: %d ###\n", info->si_value.sival_int);
//        //capta_sinal(SIGINT);
//    }
//}


/*************************************************************************/
//void tempo_sinal(int sig, siginfo_t *info, void *context){
//
//    sinal_recebido.sival_int = sig_recebido = RDTSC(); // Pega o clock do recebimento
//    if ( sigqueue(ppid, SIGUSR1, sinal_recebido) == -1 ) {                                         
//        perror("Erro no sigqueue do PAI");                                                               
//        capta_sinal(SIGINT);                                                               
//    }  
//    cont_sinal++;
//    //memcpy(&antigo, &info->si_int, sizeof( info->si_int) ); // Pega o clock carregado no sinal quando foi gerado
//    memcpy(&inicio.tv_nsec, &info->si_int, sizeof( info->si_int) ); // Pega o clock carregado no sinal quando foi gerado
//    
//    //info->_sifields._timer
//    resul    = sig_recebido - inicio.tv_nsec;                  // Clock final - Clock inicial
//    double r = ( (double)resul / 3600000000.0 ) / 1000;  // Resultado em clock divido pelo clock travado da CPU
//                                                         // Pq para cada 1s 3.6 Bilhoes de insns sao executadas por segundo
//                                                         // O resultado eh um tempo em nano segundos dividindo por 1000 temos
//                                                         // microsegundos
//
//    // TODO
//    // Travar o programa eBPF para que o RDTSC pegue o timestamp da CPU que foi travado sempre
//    // para quando for calcular o tempo o timestamp seja sempre na mesma CPU
//    // --> Travar na mesma CPU que o processo filho(CPU 5)
//    
//    //printf("(pkt:%d) Sinal recebido do kernel tempo: %lld - %lld = %f | %.2f us\n", cont_sinal, sinal_recebido , antigo, (sinal_recebido - antigo) / 3600000000.0 , r);
//    //printf("(pkt:%d) Sinal recebido do kernel tempo: %d\n", cont_sinal, antigo);
//    //printf("-->PPID: %d\n", ppid);
//
//    printf("CPU: %d | <pkt:%d | PID:%d> Sinal recebido do kernel: %lld\n", sched_getcpu() , cont_sinal, getpid(), info->si_int + (long long int)0); 
//    return;
//}

/*************************************************************************/
static __always_inline void busy_wait_cycles(unsigned long long cycles) {
    volatile unsigned long long i = 0;
    for (; i < SIMULATED_CYCLES; i++) {}
    //while(i < SIMULATED_CYCLES){ i++; }
}

/*************************************************************************/
static __always_inline uint16_t checksum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

/*************************************************************************/
int sockfd;
unsigned char buffer[BUF_SIZE];

// Se colocar essa directiva para o compilador diminui em 20us
// Essa funcao retorna true caso o pkt foi processado e false caso deu erro
// Assim n volta para a funcao recebe_teste_RX n desaloca a umem
static __always_inline int responde_pacote(uint64_t addr, uint32_t len){

    //printf("<Entrou em responde pacote>\n");

    uint8_t *pkt = xsk_umem__get_data(buffer_do_pacote, addr); 
    uint32_t tx_idx = 0;

    char *interface = "veth2";
    // Get interface index
    struct ifreq if_idx, if_mac;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(sockfd_udp, SIOCGIFINDEX, &if_idx);

    // Get MAC address
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, interface, IFNAMSIZ - 1);
    ioctl(sockfd_udp, SIOCGIFHWADDR, &if_mac);

    /*************************************/
    
    struct ethhdr *eth = (struct ethhdr *)pkt;
    struct iphdr  *ip  = (struct iphdr  *)(eth + 1);
    struct udphdr *udp = (struct udphdr *)(ip + 1);

    char *payload = (char *)(udp + 1);

    // Swap MAC addresses
    unsigned char tmp_mac[ETH_ALEN];
    memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    //memcpy(eth->h_source, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // Swap IPs
    //__u16 tmp_port;
    uint32_t tmp_ip;
    tmp_ip    = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;

    // Swap ports
    //uint16_t tmp_ip;
    uint16_t tmp_port;
    tmp_port    = udp->source;
    udp->source = udp->dest;
    udp->dest   = tmp_port;

    // Modify payload
    const char *response = "Processado (cru)";
    size_t response_len = strlen(response);
    memcpy((char *)(udp + 1), response, response_len);

    // Adjust lengths
    udp->len = htons(sizeof(struct udphdr) + response_len);
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + response_len);

    // Recalculate checksums
    ip->check = 0;
    ip->check = checksum((uint16_t *)ip, sizeof(struct iphdr));
    udp->check = 0; // UDP checksum optional (set to 0)

    // Send packet
    //struct sockaddr_ll sa;
    //memset(&sa, 0, sizeof(struct sockaddr_ll));
    //sa.sll_ifindex = if_idx.ifr_ifindex;
    //sa.sll_halen = ETH_ALEN;
    //memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);

    // Simular tempo de servico
    //busy_wait_cycles(SIMULATED_CYCLES);

    //printf("\n-->FIM responde_pkt()<--\n");
    // ENVIA PACOTE PELO SOCKET UDP
    //ssize_t sent_len = sendto(sockfd_udp, pkt, sizeof(struct ethhdr) + ntohs(ip->tot_len), 
    //                          0, (struct sockaddr *)&sa, sizeof(sa));
    //if (sent_len < 0) {
    //    perror("+++ sendto +++");
    //} else {
    //    //printf("+++ Replied to client. +++\n");
    //}
    

    //int ret = xsk_ring_prod__reserve(&umem_info2->tx, 1, &tx_idx);
    int ret = xsk_ring_prod__reserve(&umem_info->tx, 1, &tx_idx);
    if (ret != 1) {
        /* No more transmit slots, drop the packet */
        return false;
    }

    xsk_ring_prod__tx_desc(&umem_info->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&umem_info->tx, tx_idx)->len = len;
    xsk_ring_prod__submit( &umem_info->tx, 1);

    ptr_mem_info_global->tx_restante++;
    return true;
}

/*************************************************************************/

/*static __always_inline*/ void recebe_teste_RX(struct xsk_info_global *info_global){
    //pid_t tid = pthread_self();
    //printf("<Entrou recebe_RX com a thread:%ld>\n", /*gettid()*/ syscall(SYS_gettid));
    //printf("<Entrou em recebe_RX>\n");
    
    /**************************************************************/
    int i =0;

    __u32 ret_ring=0, stock_frames=0;
    __uint64_t cont_pkt=0;
    uint32_t idx_rx = 0;
    uint32_t idx_fq = 0;
    uint64_t addr;
    uint32_t len; 

    //ret_ring=0, stock_frames=0;
    //cont_pkt=0;
    //idx_rx = 0;
    //idx_fq = 0;
    //addr = 0;
    //len  = 0; 

     //while(1){
     int sigrtmin1 = SIGRTMIN+1;
     //while( sigwait(&set, &sig_usr1) == 0 ){
     while( sigwait(&set, &sigrtmin1) == 0 ){
            // esse laco pode ser o equivalente a funcao handle_receive_packets
            // do advanced03-AF-XDP
            idx_rx = 0;
            idx_fq = 0;
            i = 0;
            //addr = 0;
            //len  = 0; 
            //ret_ring=0, stock_frames=0;

            // Verifica se há pacotes no ring buffer de recepção
            // xsk_ring_cons_peek(ANEL_RX, tam_do_lote, )
            // Essa funcao no exemplo advanced03 tbm retorna 0
            //ret_ring = xsk_ring_cons__peek(&umem_info2->rx, 64, &idx_rx);
            ret_ring = xsk_ring_cons__peek(&umem_info->rx, 64, &idx_rx);

            //printf("\nVALOR DO ret_ring %d\n", ret_ring);
            //printf("valor do umem_frame_free: %d\n", *info_global->umem_frame_free);

            if( !ret_ring ){
                //raise(SIGUSR2);
                //printf("\n\n <ret_ring deu zero>\n");
                continue;
            }

            ptr_mem_info_global->ret_ring = ret_ring;

            // Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
            // retorna o endereco do pacote --> __u64 address of the packet.
            //stock_frames = xsk_prod_nb_free(&umem_info->fq,	*info_global->umem_frame_free);
            stock_frames = xsk_prod_nb_free(&umem_info->fq,	ptr_mem_info_global->umem_frame_free);
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
                    //*xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(info_global->umem_frame_addr, info_global->umem_frame_free);
                    //printf("\n(recebe_teste_RX)--- Alocando mem ---\n");
                    *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free);
                }
                // Submit the filled slots so the kernel can process them
                xsk_ring_prod__submit(&umem_info->fq, stock_frames);
            }

            /* Process received packets */
            for (i = 0; i < ret_ring; i++) {
                // xsk_ring_cons__rx_desc() --> This function is used to retrieve the receive descriptor at a specific index in the Rx ring
                //addr = xsk_ring_cons__rx_desc(&umem_info2->rx, idx_rx)->addr;
                //len  = xsk_ring_cons__rx_desc(&umem_info2->rx, idx_rx++)->len;
                addr = xsk_ring_cons__rx_desc(&umem_info->rx, idx_rx)->addr;
                len  = xsk_ring_cons__rx_desc(&umem_info->rx, idx_rx++)->len;

                //cont_pkt++;
                //printf("Tamanho do pacote recebido %d | num pkt:%ld\n", len, cont_pkt);

                // CHAMA PROCESSA_PACOTE
                //if (!processa_pacote(umem_info,  addr, len))
                //if ( !processa_pacote( addr, len) )
                if ( !responde_pacote( addr, len) ){
                    printf("(recebe_teste_RX) chamando desaloca_umem_frame | umem_frame_free: %d\n", ptr_mem_info_global->umem_frame_free);
                    //desaloca_umem_frame(info_global->umem_frame_addr, info_global->umem_frame_free, addr);
                    desaloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free, addr);

                    //printf("VOLTOU do desaloca_umem_frame\n");
                }


            }
            //*ptr_trava = 1;
            //printf("\nSAIU do FOR\n");

            //printf("### %ln %d %d\n", ptr_mem_info_global->umem_frame_addr, ptr_mem_info_global->umem_frame_free, ptr_mem_info_global->tx_restante);
            
            xsk_ring_cons__release(&umem_info->rx, ptr_mem_info_global->ret_ring);

            complete_tx(ptr_mem_info_global->umem_frame_addr, 
                    &ptr_mem_info_global->umem_frame_free, 
                    &ptr_mem_info_global->tx_restante);

            //printf("VOLTOU DO complete_tx\n");
            /*********************/
    }// laco do while
}// laco da funcao recebe_teste_RX()

/*******************************************************************************************************/

struct sockaddr_ll sa;
struct ifreq if_idx, if_mac;
uint8_t *pkt;

int pkt_cont=0;
static __always_inline int responde_pacote2(uint64_t addr, uint32_t len){

    //printf("<Entrou em responde_pacote2>\n");

    uint8_t *pkt = xsk_umem__get_data(buffer_do_pacote, addr); 
    sock_udp->pkt = pkt; // Passa o endereco do pacote para a mem compart.
    uint32_t tx_idx = 0;

    
    //char *interface = "veth4";
    // Get interface index
    struct ifreq if_idx, if_mac;
    memset(&if_idx, 0, sizeof(struct ifreq));
    //strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);
    strncpy(if_idx.ifr_name, veth2, IFNAMSIZ - 1);
    //ioctl(sockfd_udp, SIOCGIFINDEX, &if_idx);
    ioctl(sock_udp->sockUDP, SIOCGIFINDEX, &if_idx);

    //// Get MAC address
    //memset(&if_mac, 0, sizeof(struct ifreq));
    //strncpy(if_mac.ifr_name, interface, IFNAMSIZ - 1);
    //ioctl(sockfd_udp, SIOCGIFHWADDR, &if_mac);

    /*************************************/
    
    struct ethhdr *eth = (struct ethhdr *)pkt;
    struct iphdr  *ip  = (struct iphdr  *)(eth + 1);
    struct udphdr *udp = (struct udphdr *)(ip + 1);

    char *payload = (char *)(udp + 1);

    // Swap MAC addresses
    unsigned char tmp_mac[ETH_ALEN];
    memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    //memcpy(eth->h_source, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // Swap IPs
    //__u16 tmp_port;
    uint32_t tmp_ip;
    tmp_ip    = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;


    // Swap ports
    //uint16_t tmp_ip;
    uint16_t tmp_port;
    tmp_port    = udp->source;
    udp->source = udp->dest;
    udp->dest   = tmp_port;

    // Modify payload
    /*const*/ char response[20] = "Processado (cru)";
    /*size_t*/ int response_len = strlen(response);
    memcpy((char *)(udp + 1), response, response_len);

    // Adjust lengths
    udp->len = htons(sizeof(struct udphdr) + response_len );
    //ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + response_len - 2);
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + response_len);

    // Recalculate checksums
    ip->check = 0;
    ip->check = checksum((uint16_t *)ip, sizeof(struct iphdr));
    udp->check = 0; // UDP checksum optional (set to 0)

    // Send packet
    //struct sockaddr_ll sa;
    memset(&sock_udp->sa, 0, sizeof(struct sockaddr_ll));
    sock_udp->sa.sll_ifindex = if_idx.ifr_ifindex;
    sock_udp->sa.sll_halen = ETH_ALEN;
    //memcpy(sa.sll_addr, eth->h_dest, ETH_ALEN);
    memcpy(sock_udp->sa.sll_addr, eth->h_dest, ETH_ALEN);
    /************************************************************************/

    //int ret = xsk_ring_prod__reserve(&umem_info2->tx, 1, &tx_idx);
    int ret = xsk_ring_prod__reserve(&umem_info2->tx, 1, &tx_idx);
    if (ret != 1) {
        /* No more transmit slots, drop the packet */
        return false;
    }

    xsk_ring_prod__tx_desc(&umem_info2->tx, tx_idx)->addr = addr;
    xsk_ring_prod__tx_desc(&umem_info2->tx, tx_idx)->len  = len;
    xsk_ring_prod__submit( &umem_info2->tx, 1);
 
    //umem_info->tx_restante++;
    //info_global-> tx_restante++;
    ptr_mem_info_global->tx_restante++;
    /************************************************************************/

    // Simular tempo de servico
    //busy_wait_cycles(SIMULATED_CYCLES);

    // ENVIA PACOTE PELO SOCKET UDP
    //printf("Enviando pacote(%d) ...\n", ++pkt_cont);
    //sock_udp->tam_pkt = tam_pkt = sizeof(struct ethhdr) + ntohs(ip->tot_len);
    sock_udp->tam_pkt = sizeof(struct ethhdr) + htons(ip->tot_len);

    //ssize_t sent_len = sendto(sockfd_udp, pkt, sizeof(struct ethhdr) + ntohs(ip->tot_len), 0, (struct sockaddr *)&sa, sizeof(sa));
    //if (sent_len < 0) {
    //    perror("+++ sendto +++");
    //} else {
    //    printf("+++ Replied to client. +++\n");
    //}

    return false;
}


/*******************************************************************************************************/
void recebe_signal_RX2(struct xsk_info_global *info_global ){
    //printf("<Entrou em recebe_signal_RX2>\n");

    //struct sigaction act = {0};
    //act.sa_flags = SA_SIGINFO;  // Permite recebimento de sinal com dados
    //act.sa_sigaction = tempo_sinal;
    //sigemptyset(&act.sa_mask);

    //if (sigaction(SIGUSR1, &act, NULL) == -1) {
    //    perror("sigaction");
    //    capta_sinal(SIGINT);
    //}

    /**************************************************************/

    //pid_alvo = ppid;

    int i =0;

    //__u32 ret_ring=0, stock_frames=0;
    //__uint64_t cont_pkt=0;
    //uint32_t idx_rx = 0;
    //uint32_t idx_fq = 0;
    //uint64_t addr;
    //uint32_t len; 

   ret_ring= 0, stock_frames=0;
   cont_pkt= 0;
   idx_rx =  0;
   idx_fq =  0;
   addr = 0;
   len  = 0; 


     //while( sigwait(&set, &sig_usr1) == 0 ){
     while( sigwait(&set, &sigrtmin1) == 0 ){
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
                //raise( SIGUSR2 );
                //printf("\n\n<PROC_FILHO> ret_ring deu zero\n");
                //sigwait( &set , &sig );
                continue;
            }

            ptr_mem_info_global->ret_ring = ret_ring;

            //printf("(recebe_signal_RX2) ret_ring: %d\n", ptr_mem_info_global->ret_ring);
            // Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
            // retorna o endereco do pacote --> __u64 address of the packet.
            int stock_frames = xsk_prod_nb_free(&umem_info->fq,	ptr_mem_info_global->umem_frame_free);
            //printf("******************VALOR DO stock_frames %d\n", stock_frames);

            if(stock_frames > 0){
                // Reserve one or more slots in a producer ring.
                // retorna --> __u32 number of slots that were successfully reserved (idx) on success, or a 0 in case of failure.
                int ret_res = xsk_ring_prod__reserve(&umem_info->fq, stock_frames, &idx_fq);

                /* This should not happen, but just in case */
               	//while (ret_res != stock_frames)
                //    ret_res = xsk_ring_prod__reserve(&umem_info->fq, ret_ring, &idx_fq);

                for (i = 0; i < stock_frames; i++){
                    //Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
                    //uint64_t temp = alloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free);

                    *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free);
                }
                // Submit the filled slots so the kernel can process them
                xsk_ring_prod__submit(&umem_info->fq, stock_frames);
            }

            /* Process received packets */
            for (i = 0; i < ret_ring; i++) {
                // xsk_ring_cons__rx_desc() --> This function is used to retrieve the receive descriptor at a specific index in the Rx ring
                addr = xsk_ring_cons__rx_desc(&umem_info2->rx, idx_rx)->addr;
                len  = xsk_ring_cons__rx_desc(&umem_info2->rx, idx_rx++)->len;

                // CHAMA PROCESSA_PACOTE
                if ( !responde_pacote2( addr, len) ){
                    desaloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free, addr);
                }
                cont_pkt++;
             }

            // Enviando sinal e verificando se deu erro
            //if ( kill(ppid, SIGUSR1) == -1 ) {
            if ( kill(ppid, SIGRTMIN+1) == -1 ) {
            //if ( sigqueue(pid_alvo, SIGUSR1, valor_struct) == -1 ) {
                perror("Erro no sigqueue do filho");
                capta_sinal(SIGINT);
            }
            
            // Se bateu o limite de pkts a serem processados
            // termina o processo de maneira graciosa para o
            // gprof rodar sem problemas e salvar os dados de profiling
            if ( cont_pkt >= PKT_LIMIT ){
                //kill(pid_alvo, SIGUSR1);
                //kill(ppid, SIGUSR2);
                kill(ppid, SIGRTMIN+1);
                capta_sinal(SIGINT);
            }
        }
}
