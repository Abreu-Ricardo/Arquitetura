#include "packet.h"
#include "ebpf.skel.h"

#include <string.h>
struct ebpf *skel;

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
int media(long long unsigned int vetor[], int tam){

	long long int soma = 0;
	for(int i = 0; i < tam; i++){
		soma+=vetor[i];
	}

	soma = soma / tam;
	return soma;
}

/*************************************************************************/
int main(int argc, char **argv){

    if(argc < 2){
    	printf("<Passe o numero de pacotes para enviar> %s <num_pkts>\n", argv[0]);
	exit(1);
    }

    int NUM_PKTS = atoi(argv[1]);
    skel = ebpf__open();

    /***********************************************/
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("Erro ao configurar limite de memória bloqueada");
        exit(1);
    }
    /***********************************************/

    int sockfd, ouve_fd;
    struct sockaddr_in server_addr;
    struct message msg;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(1);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "10.10.10.1", &(server_addr.sin_addr));
    //inet_pton(AF_INET, "127.0.0.1", &(server_addr.sin_addr));

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        perror("connection failed");
        exit(1);
    }
    /***********************************************/

    int fd, fd2;
    int key = 1;

    fd  = bpf_obj_get("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/sock_ops_map");
    fd2 = bpf_obj_get("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/temp");
    
    bpf_map_update_elem(fd, &key, &sockfd, BPF_ANY);
    bpf_map_update_elem(fd2, &key, &sockfd, BPF_ANY);
   
    printf("Connected to server\n");

    /***********************************************/
    char buffer[1024];
    char message[] = "Oi do cliente";
    strcpy(buffer, message);

    struct iovec iov = {
        .iov_base = buffer,
        .iov_len  = sizeof(buffer)
    };
    struct msghdr rcv = {
        .msg_name    = NULL,
        .msg_namelen = 0,
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags   = 0
    };

    struct iovec resp_iov = {
        .iov_base = buffer,
        .iov_len  = sizeof(buffer)
    };
    struct msghdr resp = {
        .msg_name    = NULL,
        .msg_namelen = 0,
        .msg_iov     = &resp_iov,
        .msg_iovlen  = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags   = 0
    };
    /***********************************************/
    
    long long unsigned start,  end, *ciclos_vetor;
    ciclos_vetor = (long long unsigned *) malloc(sizeof(long long unsigned) * NUM_PKTS );
    //rcv.msg_iov->iov_base = 
    //rcv.msg_iov->iov_len = strlen(rcv.msg_iov->iov_base);

    //while (1){
    for(int i=0; i < NUM_PKTS; i++){
        // Get message from user
        printf("Enter message (or 'quit' to exit): ");
        //fgets(msg.data, BUFFER_SIZE, stdin);
        //fgets((char *)rcv.msg_iov->iov_base, BUFFER_SIZE, stdin);
        //rcv.msg_iov->iov_len = strlen(rcv.msg_iov->iov_base);
        
        //if (strcmp(msg.data, "quit\n") == 0) {
        //if (strcmp((char *)rcv.msg_iov->iov_base, "quit\n") == 0) {
        if ( i == NUM_PKTS - 1) {
            strcmp((char *)rcv.msg_iov->iov_base, "quit\n");
            break;
        }

        start = RDTSC();
        // Send message to server
        //send(sockfd, msg.data, strlen(msg.data), 0);
        if (sendmsg(sockfd, &rcv, 0) < 0){
            perror("Erro no sendmsg()");
        }
        end = RDTSC();
	
	ciclos_vetor[i] = end - start;
        //printf("Tempo gasto em us: %.2f\n", ((float)(end - start)) / 3600);
        printf("Tempo gasto em ciclos: %lld\n", (end - start));
        
        // Receive response
        //recv(sockfd, msg.data, BUFFER_SIZE, 0);
        if(recvmsg(sockfd, &resp, 0) < 0){
            perror("Erro no recvmsg()");
        }
        resp.msg_iov->iov_len = sizeof(resp.msg_iov->iov_base);
        

        //printf("Server response: %s\n", msg.data);
        char temp[200];
        strcpy(temp, (char *)resp.msg_iov->iov_base);
        //printf("Server response: %s\n", (char *)resp.msg_iov->iov_base);
        printf("Server response: %s\n", temp);
        
        memset( resp.msg_iov->iov_base, 0, sizeof(buffer));
        //memset( rcv.msg_iov->iov_base , 0, sizeof(buffer));
        memset( temp, 0, sizeof(temp));
    }

    printf("Tempo medio dos ciclos gasto em sendmsg: %d \n", media( ciclos_vetor, NUM_PKTS));

    close(sockfd);
    return 0;
}
