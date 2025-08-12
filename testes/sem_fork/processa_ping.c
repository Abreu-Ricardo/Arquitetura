#include "commons.h"
#include "xsk_kern.skel.h"

void *UMEM;

void *abre_umem(){

    int fd_umem = shm_open(nome_regiao, O_CREAT | O_RDWR, 0777);
    if (fd_umem == -1){
        perror("<processa ping>Erro em shm_open\n");
        exit(1);
    }
    int tam_regiao = NUM_FRAMES * FRAME_SIZE;

    return ( void *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_umem, 0);
    
}
/******************************************/

pid_t pega_pid(struct bpf_map *mapa, char *dir_base){
    pid_t pid;

    char temp[256];
    strcpy(temp, dir_base);
    strcat(temp, "/mapa_sinal");
    printf("### Caminho completo: ###\n%s\n", temp);

    int map_fd = bpf_obj_get(temp);
    int temp_key = 0;

    bpf_map_lookup_elem( /*bpf_map__fd(skel->maps.mapa_sinal)*/ map_fd, &temp_key, &pid);
    return pid;
}


/******************************************/
int main(int argc, char **argv){
    
    uint32_t tam_pkt_ping = 98;
    uint64_t addr;      

    sigset_t set;
    siginfo_t rcv;
    sigval_t send;

    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGRTMIN+1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q pode "ouvir"
    sigprocmask(SIG_BLOCK, &set, NULL);  

    int temp_key = 1;
    int pid = getpid();
    
    /**************************************************************/

    path = (char *) malloc(sizeof(char) * 256); // alocando tam max
    char *dir_temp = getenv("SIGSHARED");
    strcat(dir_temp, "/dados");
    printf("### Caminho ate dados: ###\n%s\n", dir_temp);

    char temp[256];
    strcpy(temp, dir_temp);
    strcat(temp, "/mapa_sinal");
    int fd_temp = bpf_obj_get(temp);

    skel = xsk_kern_bpf__open();
    if(skel == NULL) perror("Erro ao abrir o xsk_kern.bpf.o");
    bpf_map_update_elem( fd_temp, &temp_key, &pid, BPF_ANY);
    int target_pid = pega_pid(skel->maps.mapa_sinal, dir_temp);
    
    buffer_do_pacote = UMEM = abre_umem();
    if(UMEM == MAP_FAILED) perror("Erro em mmap da UMEM");
    
    
    printf("PID ALVO: %d\n", target_pid);
    printf("\nEndereco UMEM: %p\n", UMEM);

    printf("\nEsperando sinal...\n");
    while(sigwaitinfo(&set , &rcv)){
        
        addr = (uint64_t)rcv.si_value.sival_ptr;
        printf("<processa ping> addr: %ld\n", addr);
        processa_pacote(addr, tam_pkt_ping);

        send.sival_ptr = (void *)addr; 

        if(sigqueue(target_pid , sigrtmin1, send) < 0) perror("<processa ping> Erro ao enviar sinal");

    }

    return 0;
}


// Passo 1
//      pegar endereco da UMEM
//
// Passo 2
//      pegar o PID do processo original
//
//  Passo 3
//      Acessar pkt pelo deslocamento de addr e processar
//
//  Passo 4
//      sinalizar com o addr para o processo original
