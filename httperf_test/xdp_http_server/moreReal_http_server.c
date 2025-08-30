// Realistic HTTP Server in C with latency, routing, logging, and threading
// gcc real_http_server.c -o real_http_server -lpthread
// ./real_http_server
// CLIENTE: httperf --server=localhost --port=8080 --uri=/product --num-conn=1000 --rate=50

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>
#include <time.h>


#include "xsk_kern.skel.h"
#include "commons.h"

#define PORT 8080
#define BUFFER_SIZE 8192
#define MAX_CONNECTIONS 100

void *handle_client(void *arg);
void log_request(const char *client_ip, const char *request_line, int status_code);
void simulate_latency();

int main(int argc, char **argv){
    if(argc < 2){
        fprintf(stderr, "Usage: %s <network interface>\n", argv[0]);
        return 1;
    }
    

    char *path;
    const char *iface = argv[1];
    path = (char *) malloc(sizeof(char) * 256); // alocando tam max
    char *dir_temp = getenv("SIGSHARED");
   
    strcpy( path, dir_temp);
    strcat( path, "/dados");
    printf("-----------------------> %s\n%s\n", path, dir_temp);
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
    signal(SIGUSR2, capta_sinal);
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
        xsk_kern_bpf__destroy(skel);
        xsk_socket__delete(xsk);
        xsk_umem__delete(umem_info->umem);
        free(buffer_do_pacote);
        return 1;
    }

    //bpf_object__pin_maps( skel->obj , "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados");
    bpf_object__pin_maps( skel->obj , path);

    //int fd_mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "mapa_fd");
    //fd_mapa_fd = bpf_obj_get("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_fd"); 
    char mapa_fd_path[256];
    strcpy(mapa_fd_path, path);
    strcat(mapa_fd_path, "/mapa_fd");

    fd_mapa_fd = bpf_obj_get(mapa_fd_path); 
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
    //cria_segundo_socket( iface );

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
   //sigaddset(&set, SIGUSR1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q pode "ouvir"
   sigaddset(&set, SIGRTMIN+1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q pode "ouvir"
   sigaddset(&set, SIGRTMIN+2);            // Atribui o sinal SIGUSR1 para conjunto de sinais q pode "ouvir"
   pthread_sigmask(SIG_BLOCK, &set, NULL);

    pid  = 1;
    strcpy(nomeproc, argv[0]);

    pthread_t thread_complete_tx; 
    pthread_create(&thread_complete_tx, NULL, (void *)complete_tx, (void *)info_global);


    //sprintf(settar_cpup, "taskset -cp 4 %d", ppid);
    printf("\n<PID DO PAI %d>\n", ppid);
    printf("%s\nPROCESSO PAI COMECOU O WHILE E NA CPU 4\n", settar_cpup);
    system(settar_cpup);


    int chave2 =  0;
    int ret_update2 = bpf_map_update_elem( bpf_map__fd( skel->maps.mapa_sinal) , &chave2 , &ppid, BPF_ANY );
    if (ret_update2 < 0){
        perror("+++ erro ao atualizar o mapa com o PID +++");
        capta_sinal(SIGINT);
    }


    /************************CONFIGURACAO DO SERVER HTTP*******************/
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if ( setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int) ) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_CONNECTIONS) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("HTTP server listening on port %d...\n", PORT);

    int cont_pkt = 0;
    while (1) {
    //while ( sigwait(&set, &sigrtmin1) == 0  ) {


        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }
        
        recebe_signal_RX( client_fd );

        close(client_fd);

        
        //pthread_t thread_id;
        //int *pclient = malloc(sizeof(int));
        //*pclient = client_fd;
        ////pthread_create(&thread_id, NULL, handle_client, pclient);
        //pthread_create(&thread_id, NULL, (void *)recebe_signal_RX, pclient);
        //pthread_detach(thread_id);

        ////close(client_fd);
        
        printf("+++HTTP REPLY SENT(%d)+++\n", ++cont_pkt);

    }

    close(server_fd);
    return 0;
}

/****************************************************************************************/
void *handle_client(void *arg) {
    int client_fd = *((int *)arg);
    free(arg);
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    int status_code = 200;

    int received = read(client_fd, buffer, BUFFER_SIZE - 1);
    if (received <= 0) {
        close(client_fd);
        return NULL;
    }
    buffer[received] = '\0';

    char method[8], path[1024];
    sscanf(buffer, "%7s %1023s", method, path);

    simulate_latency();

    // Determine response based on path
    const char *body;
    if (strcmp(path, "/") == 0) {
        body = "<html><body><h1>Welcome to the Home Page</h1></body></html>";
    } else if (strncmp(path, "/product", 8) == 0) {
        body = "<html><body><h1>Product Page</h1></body></html>";
    } else if (strncmp(path, "/error", 6) == 0) {
        body = "<html><body><h1>Internal Server Error</h1></body></html>";
        status_code = 500;
    } else {
        body = "<html><body><h1>404 Not Found</h1></body></html>";
        status_code = 404;
    }

    // Build HTTP response
    snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %lu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status_code,
        status_code == 200 ? "OK" : status_code == 404 ? "Not Found" : "Internal Server Error",
        strlen(body),
        body);

    write(client_fd, response, strlen(response));

    // Log the request
    log_request("127.0.0.1", path, status_code);

    close(client_fd);
    return NULL;
}

/****************************************************************************************/
void log_request(const char *client_ip, const char *request_line, int status_code) {
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S %z", localtime(&now));
    printf("%s - - [%s] \"GET %s HTTP/1.1\" %d\n", client_ip, time_str, request_line, status_code);
}

/****************************************************************************************/
void simulate_latency() {
    usleep(1000 + rand() % 5000); // Simulate 1-6ms delay
}
