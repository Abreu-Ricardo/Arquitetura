#include "xsk_kern.skel.h"
#include "commons.h"

static char MSG_UDP[30] = "PODE IR";
int *ptr_udp_trava;


/******************************************************************************/
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <network interface> <single/duo>\n", argv[0]);
        return 1;
    }

    // single --> 1 socket  XDP
    // duo    --> 2 sockets XDP
    if ( strcmp(argv[2], "single") == 0){
        flag_sockXDP = 1;
    }
    else if(  strcmp(argv[2], "duo") == 0 ){
        flag_sockXDP = 2;
    }

    char settar_cpup[30]; 
    sprintf(settar_cpup, "taskset -cp 4 %d", getpid());
    system(settar_cpup);


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

    bpf_object__pin_maps( /*bpf_obj*/ skel->obj , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados");
    //int fd_mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "mapa_fd");
    fd_mapa_fd = bpf_obj_get("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_fd"); 
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
    
    //ptr_udp_trava = (char *) mmap(0, tam_trava, PROT_WRITE, MAP_SHARED, fd_trava, 0);
    //ptr_udp_trava = (int *) mmap(0, tam_trava, PROT_WRITE, MAP_SHARED, fd_trava, 0);
    ptr_udp_trava = (int *) mmap(0, tam_trava, PROT_WRITE, MAP_SHARED, fd_trava, 0);
    //*ptr_udp_trava = 0;
    

    /*###############################CRIAÇÃO DA REGIÃO DE MEM COMPART MEM_INFO_GLOBAL###################################################*/
    
    ptr_mem_info_global = (struct xsk_info_global *) malloc( sizeof(struct xsk_info_global));

    fd_info_global = shm_open(nome_info_global, O_CREAT | O_RDWR, 0777);
    if (fd_info_global == -1){
        perror("Erro em shm_open de info_global\n");
        exit(1);
    }

    tam_info_global = sizeof(struct xsk_info_global);// * 100;

    ret_ftruncate = ftruncate(fd_info_global, tam_regiao);
    if ( ret_ftruncate == -1 ){
        perror("Erro em ftruncate\n");
        exit(1);
    }

    ptr_mem_info_global   = ( struct xsk_info_global *) mmap(0, tam_info_global, PROT_WRITE, MAP_SHARED, fd_info_global, 0);

    /*###############################FIM DO CARREGAMENTO DO PROGRAMA###################################################*/
    
    configura_umem();
    configura_socket( iface );
    printf("Configurando primeiro socket...\n");
    if (flag_sockXDP == 2){
        cria_segundo_socket( iface );
        printf("Configurando segundo socket...\n");
    }

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
        xsk_kern_bpf__destroy(skel);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }
    
    info_global = (struct xsk_info_global *) malloc( sizeof(*info_global ) );
    //info_global = (struct xsk_info_global *) malloc( sizeof(struct xsk_info_global ) );
   
    info_global->umem_frame_addr = umem_frame_addr;
    info_global->umem_frame_free = umem_frame_free;
    info_global->ret_ring        = ret_ring;

    // Apos o fork essa var(ptr_mem_info_global) fica compartilhada entre os dois processos
    memcpy(ptr_mem_info_global , info_global , sizeof(*info_global));
    printf("------------ umem_frame_addr[2]:%ld\n", ptr_mem_info_global->umem_frame_addr[2]);


    /*******************************************************************************************/
    // Carregando os buffers
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++){
    	//xsk_ring_prod__fill_addr() --> Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.

        //retorna o endereco do pacote
        *xsk_ring_prod__fill_addr(&umem_info->fq, idx++) = alloca_umem_frame(ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free);
    }

    // xsk_ring_prod__submit() --> Submit the filled slots so the kernel can process them.
   	xsk_ring_prod__submit(&umem_info->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
    /*******************************************************************************************/


    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGUSR1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q ode "ouvir"
    sigprocmask(SIG_BLOCK, &set, NULL);  // Aplica o conjunto q pode "ouvir"

    //signal( SIGUSR1 , capta_sinal );
    ppid = getpid();



    // ############################## CRIANDO SOCKETS PARA ENVIO DE UDP #############################
    
    
    // ############################## FIM SOCKETS PARA ENVIO DE UDP #############################

    // 1 SOCKET XDP
    if (flag_sockXDP == 1){
        printf("Processo com um socket iniciado...\n");

        // Atualiza mapa com pid do proc atual
        int chave2 =  0;
        int ret_update2 = bpf_map_update_elem( bpf_map__fd( skel->maps.mapa_sinal) , &chave2 , &ppid, BPF_ANY );
        if (ret_update2 < 0){
            perror("+++ erro ao atualizar o mapa com o PID +++");
            capta_sinal(SIGINT);
        }

        strcpy(nomeproc, argv[0]);
        char *interface = argv[1];
        unsigned char buffer[BUF_SIZE];

        //if ((sockfd_udp = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
        //    perror("Socket");
        //    exit(EXIT_FAILURE);
        //}

        printf("Listening on %s | PKT_LIMIT: %d\n", interface, PKT_LIMIT);
        recebe_teste_RX(ptr_mem_info_global);
    }

    // 2 SOCKET XDP
    else if(flag_sockXDP == 2){
        pid = fork();

        // Processo Filho
        if(pid == 0){

            strncpy(argv[0], "loadF", strlen(argv[0]));
            fpid = getpid();
            char *interface = argv[1];
            //int sockfd_udp;
            unsigned char buffer[BUF_SIZE];

            //if ((sockfd_udp = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
            //    perror("Socket");
            //    exit(EXIT_FAILURE);
            //}

            sprintf(settar_cpup, "taskset -cp 5 %d", fpid);
            system(settar_cpup);

            if( setsid() < 0 )
                exit(-1);

            fd_namespace = open( "/proc/17517/ns/net",  O_RDONLY );
            ret_sys = syscall( __NR_setns, fd_namespace ,  CLONE_NEWNET /*0*/ );
            if (ret_sys < 0){
                printf("+++ Verificar se o processo do container esta correto. Checar com 'lsns --type=net +++'\n");
                perror("\n\nNao foi possivel mover o processo");
            }


            printf("\n<PID DO FILHO %d>\n", fpid);
            printf("Listening on %s...\n", interface);

            int chave2 =  0;
            int ret_update2 = bpf_map_update_elem( bpf_map__fd( skel->maps.mapa_sinal) , &chave2 , &fpid, BPF_ANY );
            if (ret_update2 < 0){
                perror("+++ erro ao atualizar o mapa com o PID +++");
                capta_sinal(SIGINT);
            }

            //recebe_teste_RX(ptr_mem_info_global);
            recebe_signal_RX2(ptr_mem_info_global);
        }

        // Processo Pai
        else if(pid > 0){
            printf("Processo com 2 sockets iniciados | PKT_LIMIT: %d\n", PKT_LIMIT);
            strncpy(argv[0], "loadP", strlen(argv[0]));

            //ppid = getpid();
            char settar_cpup[30]; 

            sprintf(settar_cpup, "taskset -cp 4 %d", ppid );
            printf("\n<PID DO PAI %d>\n", ppid);
            printf("%s\nPROCESSO PAI COMECOU O WHILE E NA CPU 4\n", settar_cpup);
            system(settar_cpup);

            //fpid = *ptr_trava;

            while(1){
                if( sigwait(&set, &sig_usr1) >= 0 ){
                    //printf("<PAI> PID do filho %d\n", fpid);
                    
                    //ssize_t sent_len = sendto(sockfd_udp, pkt, sizeof(struct ethhdr) + ntohs(ip->tot_len), 
                    //        0, (struct sockaddr *)&sa, sizeof(sa));
                    //if (sent_len < 0) {
                    //    perror("+++ sendto +++");
                    //} else {
                    //    //printf("+++ Replied to client. +++\n");
                    //}
                    //printf("(PROC_PAI) %d\n", ptr_mem_info_global->ret_ring);
                    
                    xsk_ring_cons__release(&umem_info2->rx, ptr_mem_info_global->ret_ring);
                    complete_tx2(ptr_mem_info_global->umem_frame_addr, 
                                &ptr_mem_info_global->umem_frame_free, 
                                &ptr_mem_info_global->tx_restante);

                    //printf("(PROC_PAI)Valor do umem_frame_free: %d\n", ptr_mem_info_global->umem_frame_free);
                    
                    //printf("(PROC_PAI2) %d\n", ptr_mem_info_global->ret_ring);
                    //complete_tx2();
                }
            } 
        }
    }
    close(sockfd_udp);
    return 0;
}

