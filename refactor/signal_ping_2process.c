#include "xsk_kern.skel.h"
#include "commons.h"


/*************************************************************************/
static __always_inline volatile long long RDTSC() {
    
    //register long long TSC asm("eax");
    //asm volatile (".byte 15, 49" : : : "eax", "edx");
    //return TSC;

    unsigned int lo, hi;
    
    asm ("rdtsc" : "=a" (lo), "=d" (hi)); // Execute RDTSC and store results
    return ((long long)hi << 32) | lo;            // Combine high and low parts
} 


/*************************************************************************/
int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <network interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    //const char *iface = "veth2";

    // Atribuindo PROC_PAI a CPU 4 logo cedo
    ppid = getpid();
    char settar_cpup[30]; 
    sprintf(settar_cpup, "taskset -cp 4 %d", ppid);
    system(settar_cpup);


    /***************Config da regiao de mem compart com shm*****************/
    char     *caminho_prog = "xsk_kern.o";
    char     *ptr_fim_regiao;
    uint64_t *ptr_regiao;
    
    signal(SIGINT , capta_sinal);
    //signal(SIGUSR1, teste);
    //signal(33, capta_sinal);


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
    //ifindex = if_nametoindex(iface);
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

    // Aclopa o programa XDP com a funcao propria da libbpf
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

    bpf_object__pin_maps( skel->obj , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados");

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

    int temp = NUM_FRAMES;
    info_global = (struct xsk_info_global *) malloc( sizeof(*info_global ) );
    info_global->umem_frame_addr = umem_frame_addr;
    info_global->umem_frame_free = umem_frame_free;
    info_global->ret_ring        = ret_ring;
    // Apos o fork essa var(ptr_mem_info_global) fica compartilhada entre os dois processos
    memcpy(ptr_mem_info_global , info_global , sizeof(*info_global));
    printf("------------ umem_frame_addr[2]:%ld\n", ptr_mem_info_global->umem_frame_addr[2]);
    
    // Carregando os buffers
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++){
    	//xsk_ring_prod__fill_addr() --> Use this function to get a pointer to a slot in the fill ring to set the address of a packet buffer.

        //retorna o endereco do pacote
        //*xsk_ring_prod__fill_addr(&umem_info->fq, idx++) = alloca_umem_frame(umem_frame_addr, &umem_frame_free);
        *xsk_ring_prod__fill_addr(&umem_info->fq, idx++) = alloca_umem_frame( ptr_mem_info_global->umem_frame_addr, &ptr_mem_info_global->umem_frame_free);
    }

    // xsk_ring_prod__submit() --> Submit the filled slots so the kernel can process them.
   	xsk_ring_prod__submit(&umem_info->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
    
    



    /* Bloqueia o sinal para nao executar o mecanismo padrao */
   sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
   sigaddset(&set, SIGUSR1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q pode "ouvir"
   sigprocmask(SIG_BLOCK, &set, NULL);  // Aplica o conjunto q pode "ouvir"

    //act.sa_flags     = SA_SIGINFO | SA_NODEFER;  // Permite recebimento de sinal com dados
    //act.sa_sigaction = teste; //signal_handler;
    //sigemptyset(&act.sa_mask);


    //signal( SIGUSR1 , capta_sinal );
    //ppid = getpid();
    pid  = fork();
    strcpy(nomeproc, argv[0]);

    // ############################## PROCESSAMENTO DOS PACOTE #############################
    // Processo filho
    if( pid == 0){
        // Trocando o nome do processo para poolpingPAI
        strncpy(argv[0], "sig_FIL", strlen(argv[0]));
        
        fpid = getpid();
        char settar_cpuf[30];
        
        // Atribui o valor do PID do filho para que o proc pai consiga enviar o sinal
        memcpy(ptr_trava, &fpid, sizeof(fpid));
        
        printf("\n<PID DO FILHO %d>\n", fpid);
        
        if( setsid() < 0 )
            exit(-1);

        // PID do namespace pego com lsns --type=net dentro do container
        fd_namespace = open( "/proc/14707/ns/net",  O_RDONLY );
        ret_sys = syscall( __NR_setns, fd_namespace ,  CLONE_NEWNET /*0*/ );
        if (ret_sys < 0){
            printf("+++ Verificar se o processo do container esta correto. Checar com 'lsns --type=net +++'\n");
            perror("\n\nNao foi possivel mover o processo");
        }
        
        sprintf(settar_cpuf, "taskset -cp 5 %d", fpid);
        system(settar_cpuf);
       
        int chave2 =  0;
        int ret_update2 = bpf_map_update_elem( bpf_map__fd( skel->maps.mapa_sinal) , &chave2 , &fpid, BPF_ANY );
        if (ret_update2 < 0){
            perror("+++ erro ao atualizar o mapa com o PID +++");
            capta_sinal(SIGINT);
        }

        printf("RETORNO DA SYSCALL DO FILHO -->> %d\n\n", ret_sys);
        printf("PROCESSO FILHO CRIADO E NA CPU 5\n");

        //struct sigaction act;
        //act.sa_flags = SA_SIGINFO | SA_NODEFER ;  // Permite recebimento de sinal com dados
        //act.sa_sigaction = recebe_signal_RX;
        //sigemptyset(&act.sa_mask);


        recebe_signal_RX( ptr_mem_info_global );
    }

    // Processo pai
    else if ( pid > 0){
        // Trocando o nome do processo para poolpingPAI
        strncpy(argv[0], "sig_PAI", strlen(argv[0]));

        //ppid = getpid();
        char settar_cpup[30]; 
        
        //sprintf(settar_cpup, "taskset -cp 4 %d", ppid);
        printf("\n<PID DO PAI %d>\n", ppid);
        printf("%s\nPROCESSO PAI COMECOU O WHILE E NA CPU 4\n", settar_cpup);
        //system(settar_cpup);

        fpid = *ptr_trava;

    	//struct sigaction act;
        //act.sa_flags = SA_SIGINFO;  // Permite recebimento de sinal com dados
        //act.sa_sigaction = signal_handler;
        //sigemptyset(&act.sa_mask);


        //// Registra um handler para SIGUSR1
        //if (sigaction(SIGUSR1, &act, NULL) == -1) {
        //    perror("sigaction");
        //    capta_sinal(SIGINT);
        //}

        //union sigval valor;
        //valor.sival_int = dado;  // Anexa dado ao sinal

        // Espera pelo sinal do proc filho
        // sigwait(&set, &sig);
        while(1){
            if( sigwait(&set, &sig_usr1) >= 0 ){
                //printf("<PAI> PID do filho %d\n", fpid);
                
                   xsk_ring_cons__release(&umem_info2->rx, ptr_mem_info_global->ret_ring);
                   complete_tx(ptr_mem_info_global->umem_frame_addr, 
                               &ptr_mem_info_global->umem_frame_free, 
                               &ptr_mem_info_global->tx_restante);
                  //complete_tx();
            }
        }
    }
    else{
        perror("+++ ERRO NO FORK +++");
        capta_sinal(SIGINT);
    }
    
    return 0;
}

