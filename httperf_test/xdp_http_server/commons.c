#include "commons.h"

#include <netinet/tcp.h>
struct xsk_kern_bpf    *skel;


int *ptr_trava;
char *nome_regiao      = "/memtest";
char *nome_trava       = "/trava";
char *nome_info_global = "info_global";

struct xsk_socket *xsk;
struct xsk_socket *xsk2;
void *buffer_do_pacote; // e usar o ptr da mem compart do shm()

struct xdp_program *xdp_prog;
struct bpf_object *bpf_obj;
struct bpf_map *bpf_map;

struct xsk_kern_bpf    *skel;
struct xsk_umem_info   *umem_info;    // xsk  -- Processo
struct xsk_umem_info   *umem_info2;   // xsk2 -- Processo
struct xsk_info_global *ptr_mem_info_global;

int fd_sock_client;
struct sockaddr_in client_addr;
socklen_t client_len = sizeof(client_addr);

char nomeproc[30];
char *path;
pid_t fpid, ppid, pid_alvo;

/************************************************************************/
void capta_sinal(int signum){
    //getchar();

    if (signum == 2){
        bpf_object__unpin_maps( skel->obj , path);
   

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
        //system("rm /home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/xsk_kern_*");
       
        char cmdkill[50];
        sprintf(cmdkill, "killall %s", nomeproc);
        //system("killall pollping_ref");
        system(cmdkill);
        //kill(fpid, SIGKILL);
        raise(SIGKILL);
        
        lock = 0;
	    exit(0);
    }


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
   
    __u64 tam_umem = NUM_FRAMES * FRAME_SIZE; 
    printf("TAMANHO DA UMEM: %lld\n", tam_umem);
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

    int ret_update = xsk_socket__update_xskmap(xsk, bpf_map__fd(skel->maps.xsk_map));
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
/*__always_inline*/ uint64_t alloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free){
    
    uint64_t frame;
    //if(frame_free == 0)
    if( ptr_mem_info_global->umem_frame_free == 0 ){
        printf("Erro em alloca_umem_frame() %d\n", ptr_mem_info_global->umem_frame_free);
        return INVALID_UMEM_FRAME;
    }

   
    //frame = ptr_mem_info_global->umem_frame_addr[ --ptr_mem_info_global->umem_frame_free ];
    frame = ptr_mem_info_global->umem_frame_addr[ --ptr_mem_info_global->umem_frame_free ];
    ptr_mem_info_global->umem_frame_addr[ptr_mem_info_global->umem_frame_free] = INVALID_UMEM_FRAME;

   // printf("(alloca_umem)#### frame: %lu\n", frame);

	//frame = vetor_frame[--*frame_free];
	//vetor_frame[*frame_free] = INVALID_UMEM_FRAME;

    return frame;
}

/****************************************************************************/
static __always_inline void desaloca_umem_frame(uint64_t *vetor_frame, uint32_t *frame_free, uint64_t frame){
	
    
    assert( ptr_mem_info_global->umem_frame_free < NUM_FRAMES);

    //printf("(desaloca_umem)#### umem_frame_free: %d\n", ptr_mem_info_global->umem_frame_free);

    ptr_mem_info_global->umem_frame_addr[ ptr_mem_info_global->umem_frame_free++ ] = frame;
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

// ---- helpers ----
//uint16_t csum16_add(uint16_t csum, uint16_t addend) {
//    csum += addend;
//    return (csum + (csum < addend));
//}

//uint16_t ip_checksum(void *viphdr, size_t len) {
//    unsigned long sum = 0;
//    uint16_t *ip1 = viphdr;
//    while (len > 1) {
//        sum += *ip1++;
//        if (sum & 0x80000000)
//            sum = (sum & 0xFFFF) + (sum >> 16);
//        len -= 2;
//    }
//    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
//    return (uint16_t)(~sum);
//}

//uint16_t ip_checksum(uint16_t *ptr, int len) {
uint16_t ip_checksum(void *ptr, int len) {
    uint32_t sum = 0;
    uint16_t *data = ptr;

    while (len > 1) {
        sum += *data++;
        if (sum & 0x10000) {   // carry occurred
            sum = (sum & 0xFFFF) + 1;
        }
        len -= 2;
    }

    if (len == 1) {
        sum += *((uint8_t *)data);
    }

    return ~((uint16_t)sum);
}


uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, uint8_t *payload, int payload_len) {
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t tcp_len;
    } pseudo;

    pseudo.src = iph->saddr;
    pseudo.dst = iph->daddr;
    pseudo.zero = 0;
    pseudo.proto = IPPROTO_TCP;
    pseudo.tcp_len = htons(sizeof(struct tcphdr) + payload_len);

    //printf("AAAAAAAAAAAA %d %d\n", iph->saddr, iph->daddr);

    uint32_t total_len = sizeof(pseudo) + sizeof(struct tcphdr) + payload_len;
    uint8_t *buf = malloc(total_len);
    memcpy(buf, &pseudo, sizeof(pseudo));
    memcpy(buf + sizeof(pseudo), tcph, sizeof(struct tcphdr));
    memcpy(buf + sizeof(pseudo) + sizeof(struct tcphdr), payload, payload_len);

    uint16_t result = ip_checksum(buf, total_len);

    free(buf);
    return result;
}

// ---- main packet processor ----
int processa_pacote(uint64_t addr, uint32_t len, int client_fd) {
    uint8_t *pkt = xsk_umem__get_data(buffer_do_pacote, addr);

    struct ethhdr *eth = (struct ethhdr *) pkt;
    struct iphdr  *ip  = (struct iphdr *)(eth + 1);
    int iphdr_len = ip->ihl * 4;
    
    struct tcphdr *tcph = (struct tcphdr *)((uint8_t *)ip + iphdr_len);
    int tcphdr_len = tcph->doff * 4;
    
    uint8_t *payload = (uint8_t *)tcph + tcphdr_len;
    int payload_len = ntohs(ip->tot_len) - iphdr_len - tcphdr_len;

    if (payload_len <= 0) return -1;

    // ---- swap MACs ----
    uint8_t tmp_mac[ETH_ALEN];
    memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp_mac, ETH_ALEN);
    /*****************************************************************************/

    //printf("IP ANT: %d %d\n",ntohl(ip->saddr), ntohl(ip->daddr));
    // ---- swap IPs ----
    uint32_t tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    ////printf("IP DPS: %d %d\n", ntohl(ip->saddr), ntohl(ip->daddr));

    ///*****************************************************************************/
    ////printf("PORT ANT: %d %d\n",tcph->source, tcph->dest);
    //// ---- swap ports ----
    uint16_t tmp_port = tcph->source;
    tcph->source = tcph->dest;
    tcph->dest   = tmp_port;
    //printf("PORT DPS: %d %d\n",tcph->source, tcph->dest);

    /*****************************************************************************/
    // ---- build HTTP response ----
    const char *body = "<html><body><h1>Hello from AF_XDP!</h1></body></html>";
    char *resp_ptr = (char *)payload;
    int resp_len = snprintf(resp_ptr, 1500 - (resp_ptr - (char*)pkt),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        strlen(body), body);

    printf("%s\n\n", payload);
    // ---- fix IP header ----
    ip->tot_len = htons(iphdr_len + tcphdr_len + resp_len);
    ip->protocol = IPPROTO_TCP;
    
    ////printf("\n### antigo ip_checksum: %d ###\n", ip->check);
    ip->check = 0;
    ip->check = ip_checksum(ip, iphdr_len);
    ////printf("\n### novo ip_checksum: %d ###\n", ip->check);

    //// ---- fix TCP header ----
    tcph->psh = 1;
    tcph->ack = 1;
    ////tcph->th_flags = 0x10;
    
    tcph->fin = 0; tcph->syn = 0; tcph->rst = 0;
    tcph->psh = 1; tcph->ack = 1;
    tcph->urg = 0; //tcph->ece = 0; tcph->cwr = 0;
    tcph->urg_ptr = 0;
    tcph->window = htons(65535);

    //// fake seq/ack: swap
    uint32_t old_seq = ntohl(tcph->seq);
    uint32_t old_ack = ntohl(tcph->ack_seq);
    //tcph->ack_seq    = htonl(old_seq + payload_len); // acknowledge request
    tcph->ack_seq = htonl(old_seq + resp_len); // acknowledge request
    tcph->seq     = htonl(old_ack);               // continue from ack number

    //////printf("\n### antigo tcp_checksum: %d ###\n", tcph->check);
    tcph->check = 0;
    //tcph->check = tcp_checksum(ip, tcph, (uint8_t *)resp_ptr, resp_len);
    tcph->check = tcp_checksum(ip, tcph, payload, payload_len);
    //printf("\n### novo tcp_checksum: %d ###\n", tcph->check);

    //write(client_fd, payload, payload_len);
    //write(client_fd, resp_ptr, resp_len);
    //if ( send(client_fd , resp_ptr, resp_len, 0) < 0){
    //    perror("ERRO NO SEND");
    //    capta_sinal(SIGINT);
    //}
    //close(client_fd);
    
    return sizeof(struct ethhdr) + iphdr_len + tcphdr_len + resp_len;
    //return resp_len; // payload_len;
}



/*************************************************************************/
int cont = 0;
//void complete_tx(uint64_t *vetor_frame, uint32_t *frame_free, uint32_t *tx_restante){
void complete_tx(struct xsk_info_global *info_global, uint32_t len, uint64_t addr, int client_fd){
    
    //printf("chamando complete_tx: %d\n", cont++);

    sigset_t set_tx;
    sigval_t send;
    siginfo_t rcv;
    int len_temp = 98;
    //uint64_t addr;

    int sigrtmin2 = SIGRTMIN+2;
    sigemptyset(&set_tx);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set_tx, SIGRTMIN+2);            // Atribui o sinal SIGUSR1 para conjunto de sinais q pode "ouvir"
    sigprocmask(SIG_BLOCK, &set_tx, NULL); 
      

        uint32_t tx_idx = 0;
        int ret = xsk_ring_prod__reserve(&umem_info->tx, 1, &tx_idx);

        if (ret != 1) {
            /* No more transmit slots, drop the packet */
            // return false;
            printf("Erro ao reservar buffer tx | ret: %d\n", ret);
        }

        //printf("(complete_tx): len do pkt a enviar %d | addr: %ld\n", len, addr);
        xsk_ring_prod__tx_desc(&umem_info->tx, tx_idx)->addr = addr;
        //xsk_ring_prod__tx_desc(&umem_info->tx, tx_idx)->len = len_temp; // len_temp --> len do icmp
        xsk_ring_prod__tx_desc(&umem_info->tx, tx_idx)->len = len;
        xsk_ring_prod__submit( &umem_info->tx, 1);

        ptr_mem_info_global->tx_restante++;
        xsk_ring_cons__release(&umem_info->rx, ptr_mem_info_global->ret_ring);

        /********************************************************************************************/

        int i, retsend; 
        unsigned int completed;
        uint32_t idx_cq;

        if (!ptr_mem_info_global->tx_restante){
            //printf("\n\n###(complete_tx) nao enviou o pkt, umem_info->tx_restante: %d\n", *tx_restante);
            return;
        }

        retsend = sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        //retsend = 0;
        //printf("Retorno do sendto: %d\n", retsend);
        close(client_fd);

        // Se retorno de sendto for < 0, houve erro 
        if (retsend >= 0){

            // Tem hora que leva 40 ciclos outras 1000+
            completed = xsk_ring_cons__peek(&umem_info->cq,	XSK_RING_CONS__DEFAULT_NUM_DESCS, &idx_cq);

            //printf("(complete_tx) valor de completed: %d\n", completed);
            if (completed > 0) {
                //printf("-->Entrou no completed<--\n");
                for (i = 0; i < completed; i++){
                    //printf("Desalocando %d\n", i);
                    desaloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free, *xsk_ring_cons__comp_addr(&umem_info->cq, idx_cq++) );
                }
                xsk_ring_cons__release(&umem_info->cq, completed);
                ptr_mem_info_global->tx_restante -= completed < ptr_mem_info_global->tx_restante ?	completed : ptr_mem_info_global->tx_restante;
            }
        }
        else{
            printf("ERRO, retorno do sendto() menor que 0, valor: %d\n\n", retsend);
            printf("*****************************\n\n");
        }
    
    return;
}


/*************************************************************************/

/*************************************************************************/

int i =0;
__u32 ret_ring=0, stock_frames=0;
__uint64_t cont_pkt=0;
uint32_t idx_rx = 0;
uint32_t idx_fq = 0;
uint64_t addr;
uint32_t len; 
uint32_t tx_idx = 0;

union sigval valor_struct;
sigset_t set;
//valor.sival_int = dado;  // Anexa dado ao sinal

//void recebe_signal_RX(struct xsk_info_global *info_global, int client_fd ){
void *recebe_signal_RX( int client_fd ){


    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
                                         //sigaddset(&set, SIGUSR1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q pode "ouvir"
    sigaddset(&set, SIGRTMIN+1);            
    /**************************************************************/


    int temp, key = 1;
    sigval_t send;
    siginfo_t rcv;

    //while( sigwait(&set, &sigrtmin1) == 0 ){
    if( sigwait(&set, &sigrtmin1) == 0 ){

        printf("\n\n+++RECEBEU O SINAL+++\n\n");
        idx_rx = 0;
        idx_fq = 0;
        i = 0;

            // Verifica se há pacotes no ring buffer de recepção
            // xsk_ring_cons_peek(ANEL_RX, tam_do_lote, )
            // Essa funcao no exemplo advanced03 tbm retorna 0
            ret_ring = xsk_ring_cons__peek(&umem_info->rx, 64, &idx_rx);

            if( !ret_ring ){
                printf("ret_ring retornou 0\n");
                //continue;
                return NULL;
            }

            ptr_mem_info_global->ret_ring = ret_ring;

            stock_frames = xsk_prod_nb_free(&umem_info->fq,	ptr_mem_info_global->umem_frame_free);
            //printf("******************VALOR DO stock_frames %d\n", stock_frames);

            if(stock_frames > 0){
                int ret_res = xsk_ring_prod__reserve(&umem_info->fq, stock_frames, &idx_fq);

                for (i = 0; i < stock_frames; i++){
                    //Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.
                    *xsk_ring_prod__fill_addr(&umem_info->fq, idx_fq++) = alloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free);
                }
                // Submit the filled slots so the kernel can process them
                xsk_ring_prod__submit(&umem_info->fq, stock_frames);
            }

            uint32_t pkt_len;
            /* Process received packets */
            for (i = 0; i < ret_ring; i++) {
                // xsk_ring_cons__rx_desc() --> This function is used to retrieve the receive descriptor at a specific index in the Rx ring
                addr = xsk_ring_cons__rx_desc(&umem_info->rx, idx_rx)->addr;
                len  = xsk_ring_cons__rx_desc(&umem_info->rx, idx_rx++)->len;

                //printf("-->Tamanho do pacote recebido %d | addr:%ld\n", len, addr);
                pkt_len = processa_pacote(addr, len, client_fd);

             }

                //printf("<--Tamanho do pacote alterado %d | addr: %ld\n", pkt_len, addr);
                complete_tx(ptr_mem_info_global, pkt_len, addr, client_fd);
                //close(client_fd);
                return NULL;
        }
    return NULL;
}

/*************************************************************************/

//void procesa_http(){
//    //int client_fd = *((int *)arg);
//    //free(arg);
//    char buffer[BUFFER_SIZE];
//    char response[BUFFER_SIZE];
//    int status_code = 200;
//
//    int received = read(client_fd, buffer, BUFFER_SIZE - 1);
//    if (received <= 0) {
//        close(client_fd);
//        return NULL;
//    }
//    buffer[received] = '\0';
//
//    char method[8], path[1024];
//    sscanf(buffer, "%7s %1023s", method, path);
//
//    //simulate_latency();
//
//    // Determine response based on path
//    const char *body;
//    if (strcmp(path, "/") == 0) {
//        body = "<html><body><h1>Welcome to the Home Page</h1></body></html>";
//    } else if (strncmp(path, "/product", 8) == 0) {
//        body = "<html><body><h1>Product Page</h1></body></html>";
//    } else if (strncmp(path, "/error", 6) == 0) {
//        body = "<html><body><h1>Internal Server Error</h1></body></html>";
//        status_code = 500;
//    } else {
//        body = "<html><body><h1>404 Not Found</h1></body></html>";
//        status_code = 404;
//    }
//
//    // Build HTTP response
//    snprintf(response, sizeof(response),
//        "HTTP/1.1 %d %s\r\n"
//        "Content-Type: text/html\r\n"
//        "Content-Length: %lu\r\n"
//        "Connection: close\r\n"
//        "\r\n"
//        "%s",
//        status_code,
//        status_code == 200 ? "OK" : status_code == 404 ? "Not Found" : "Internal Server Error",
//        strlen(body),
//        body);
//
//    write(client_fd, response, strlen(response));
//
//    // Log the request
//    log_request("127.0.0.1", path, status_code);
//
//    close(client_fd);
//    return NULL;
//
//}
//
//void log_request(const char *client_ip, const char *request_line, int status_code) {
//    time_t now = time(NULL);
//    char time_str[64];
//    strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S %z", localtime(&now));
//    printf("%s - - [%s] \"GET %s HTTP/1.1\" %d\n", client_ip, time_str, request_line, status_code);
//}
