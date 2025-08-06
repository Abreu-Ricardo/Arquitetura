#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>


#include "../bib/teste_bib.h"

struct item{
    int dado;
    struct item *prox;
};

struct ptr{
    struct item *last;
};


/*******************************************************************/
void imprime(struct item *p){

    struct item *aux;
        
    aux = p;
    while( p->prox != aux){
        printf("valor: %d\n", p->dado);
        //aux = aux->prox; 
        p += sizeof(struct item *);
    }

    // Ultimo valor antes de chegar no ponteiro de novo
    printf("valor: %d\n", aux->dado);

    return;
}

/*******************************************************************************/

int main(int argc, char **argv){

    // Tamanho e nome da regiao de mem
    const int tam_regiao = 4096;
    const char nome_regiao[50];

    // descritor e ponterios para a mem
    int fd_shm;
    char *ptr1, *ptr2;
    char *ptr3;
    int key=0;
    char temp[50];
    
    struct ptr *p1, *p2, *p3;


    struct info_ebpf bpf;
    char *caminho_prog = "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/espaco_kernel.o";


    struct bpf_object *bpf_obj;
    struct bpf_map *map;

    // # Primeiro caminho eh para rodar no espaco de usuario normal, o segundo eh para rodar entre containers
    //int mapa_fd = bpf_obj_get("/sys/fs/bpf/mapa_fd");
    int mapa_fd = bpf_obj_get("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_fd");
    if (mapa_fd < 0){
        printf("<consumidor>Erro ao obter o FD do mapa\n");
        //bpf_object__close(bpf_obj);
        return -1;
    }

    int ret_lookup = bpf_map_lookup_elem(mapa_fd, &key, (void *)nome_regiao);
    printf("\n<consumidor>nome da regiao: %s\n\n", nome_regiao);


    // Passo 1, pegar o fd local da regiao de mem compart
    // bit mask, segundo a definicao de sys/stat.h 
    // 0666 --> S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
    fd_shm = shm_open(nome_regiao, O_RDWR, 0666);
    printf("<consumidor>valor do fd_shm: %d\n", fd_shm);

    /**********************************************************************************/
    // Passo 2, mapear o codigo para o espaco de mem do processo
    ptr3 = ptr2 = ptr1 = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    struct item *pont1 = (struct item *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    if ( pont1 == MAP_FAILED ){
        perror("Erro ao obter o ponteiro de mmap");
    }

    
    ptr2 = ptr2 + tam_regiao - 1;
    printf("ptr2: %d\n", *ptr2);
 

    // Teste com o consumo de memoria sequencial em um vetor        
    //for (int i=0; i<8; i++){
    //    ptr1 += sizeof(int);
    //    printf("%s", (char *) ptr1);    
    //}

    
    for (int i=0; i<10; i++){
        printf("valor: %d endereco: %p prox: %p\n", pont1->dado, pont1, pont1->prox);
        pont1 += sizeof(struct item *);
    }

   
    *ptr2 = 1;
    while(*ptr2 == 1)
        ;

    shm_unlink(nome_regiao);

    return 0;
}
