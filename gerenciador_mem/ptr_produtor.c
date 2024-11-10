#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h> // Para a func signal()


#include "../bib/teste_bib.h"

struct info_ebpf bpf;
char *caminho_prog = "../eBPF/espaco_kernel.o";


// Para caso o programa consumidor der erro e o mapa nao ficar alocado
static void captura_sinal(){
    remove_ebpf( caminho_prog, &bpf);
    exit(0);

}

 typedef struct data{
    char dados[1500];
}buf_dados;


/***********************************************************/
int main(int argc, char **argv){

    char *ptr1, *ptr2;
    char *nome_regiao = "/memtest";
    int fd_shm;



/*  struct bpf_object *prog_obj;
    prog_obj = bpf_object__open_file( caminho_prog, NULL);
    if (prog_obj == NULL){
        printf("DEU ERRADO PEGAR O PROGRAMA\n");
        return -1;
    }
*/

    signal(SIGINT, captura_sinal);

    carrega_ebpf(caminho_prog, "teste", &bpf);
    atualiza_mapa(caminho_prog, "mapa_fd", nome_regiao, &bpf);
    le_mapa(&bpf);

/*
    int mapa_fd = bpf_object__find_map_fd_by_name(prog_obj, "mapa_fd");
    if (mapa_fd < 0){
        printf("DEU ERRADO O FD DO MAPA\n");
        return 1;    
    }
*/

    // Dados a serem escritos da mem compart
    const char *msg = "Oii, sou a msg";
    const char *msg1 = "\nOlaa, sou a msg2";

    //atualiza_mapa();
    // Cria a regiao de mem. compart.
    fd_shm = shm_open(nome_regiao, O_CREAT | O_RDWR, 0666);
    if (fd_shm == -1){
        perror("Erro em shm_open\n");
        exit(1);
    }


    // Tamanho da regiao de mem.
    //int tam_regiao = 4096;
    int tam_regiao = 800 * sizeof( buf_dados ) + 1;

    // Atribuindo tamanho para a regiao de mem. compart.
    int ret_ftruncate = ftruncate(fd_shm, tam_regiao);
    if ( ret_ftruncate == -1 ){
        perror("Erro em ftruncate\n");
        exit(1);
    }


    /*************************************************************************/
    buf_dados *p;
    // Mapeia a regiao de memoria com a seu tamanho, modo de protecao e flags especificas
    //ptr2 = ptr1 = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    p = (buf_dados *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    
    char *p_int; 
    ptr2 = p_int = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);

    if ( /**ptr1 == -1*/ p == NULL /*p_int == NULL*/  ){
        perror("Erro em mmap\n");
        exit(1);
    }

    buf_dados vetor[100];
    int vet[100];

    //for(int i=0; i <100; i++){
    //    vet[i] = i;

    //    memcpy(p_int, &vet[i], sizeof(int ));
    //    
    //    printf("--> %d i:%d\n", *p_int, i);
    //    p_int += sizeof(int *);
    //}
    struct data *teste;

    for(int i=0; i < 100; i++){
        printf("%d %s\n", i, p->dados);
        
        // Salva dados na estrutura
        sprintf(vetor[i].dados, "Valor escrito por produtor %d\n", i);
        //printf("%s", vetor[i].dados);
    

        // Copiar os dados da estrutura para a memoria compart.
        memcpy(p, &vetor[i], sizeof( buf_dados) );
        printf("Conferindo endereco: %p %s", p, p->dados );

        printf("chegeueeei \n");
        
        // Anda o ponteiro para a prox posicao 
        p = p + sizeof(struct data *);
    }


    /****************************************************************************/


    ptr2 += tam_regiao - 1;
    *ptr2 = 0;

    printf("###############\n");
    // Escrita na regiao de mem compart
    //sprintf(ptr1, "%s", msg);
    //ptr1 += strlen(msg);
    //sprintf(ptr1, "%s", msg1);
    //ptr1 += strlen(msg1);
    
    while( *ptr2 == 0 )
        ;

    *ptr2 = 0;
   

    remove_ebpf(caminho_prog, &bpf);

    return 0;
}
