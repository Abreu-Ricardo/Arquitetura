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
char *caminho_prog = "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/espaco_kernel.o";


// Para caso o programa consumidor der erro e o mapa nao ficar alocado
static void captura_sinal(){
    remove_ebpf( caminho_prog, &bpf);
    exit(0);

}
/***************************************************************************/

struct item{
    int dado;
    struct item *prox;
};

struct ptr{
    struct item *last;
};

/****************************************************************************/

void insere_lista(struct item *p, int valor, struct item *pont1){
    

    struct item *aux = (struct item *) malloc( sizeof(struct item) );

    if (aux != NULL){
        aux->dado = valor;

        // Primeiro caso: Primeiro elemento a ser inserido
        if ( p->dado == -1 ){
            p->dado = valor;
            p->prox = p;

            memcpy(pont1, p, sizeof(struct item ));
            printf("pont1 dado:%d endereco: %p prox: %p\n", pont1->dado, pont1 , pont1->prox);
            //pont1 += sizeof(struct item ); 
        }
        // Segundo caso: Demais elementos a serem inseridos
        else{
            
            struct item *aux_temp;
            aux_temp = p->prox; 

            while( aux_temp->prox != p ){ 
                //printf("LOOP %d\n", aux_temp->dado);
                aux_temp = aux_temp->prox;
            }

            aux_temp->prox = aux;
            aux->prox = p;
            
            memcpy(pont1, aux, sizeof(struct item ));
            printf("pont1 dado:%d endereco: %p prox: %p\n", pont1->dado, pont1 , pont1->prox);
    
            
            //memcpy(pont1, aux, sizeof(struct item ));
            //printf("pont1 dado:%d endereco: %p prox: %p\n", pont1->dado, pont1 , aux->prox);
            //pont1 += sizeof(struct item ); 

        }
    }


    return;
}

/********************************************************************************/
void imprime(struct item *p){

    struct item *aux;
        
    aux = p;
    while( aux->prox != p){
        printf("valor lista: %d\n", aux->dado);
        aux = aux->prox; 
    }

    // Ultimo valor antes de chegar no ponteiro de novo
    printf("valor lista: %d\n", aux->dado);

    return;
}


/***************************************************************************/
int main(int argc, char **argv){

    char *ptr1, *ptr2, *ptr3;
    char *nome_regiao = "/memtest";
    int fd_shm;

    struct item *p1 = (struct item *) malloc(sizeof(struct item));
    p1->dado = -1;


/*  struct bpf_object *prog_obj;
    prog_obj = bpf_object__open_file( caminho_prog, NULL);
    if (prog_obj == NULL){
        printf("DEU ERRADO PEGAR O PROGRAMA\n");
        return -1;
    }
*/

/*
    int mapa_fd = bpf_object__find_map_fd_by_name(prog_obj, "mapa_fd");
    if (mapa_fd < 0){
        printf("DEU ERRADO O FD DO MAPA\n");
        return 1;    
    }
*/
    
    /******************************************/
    signal(SIGINT, captura_sinal);

    carrega_ebpf(caminho_prog, "teste", &bpf);
    atualiza_mapa(caminho_prog, "mapa_fd", nome_regiao, &bpf);
    le_mapa(&bpf);
    /******************************************/


    // Dados a serem escritos da mem compart
    //const char *msg = "Oii, sou a msg";
    //const char *msg1 = "\nOlaa, sou a msg2";

    //atualiza_mapa();
    

    // Cria a regiao de mem. compart.
    fd_shm = shm_open(nome_regiao, O_CREAT | O_RDWR, 0666);
    if (fd_shm == -1){
        perror("Erro em shm_open\n");
        exit(1);
    }
    // Tamanho da regiao de mem.
    int tam_regiao = 4096;

    // Atribuindo tamanho para a regiao de mem. compart.
    int ret_ftruncate = ftruncate(fd_shm, tam_regiao);
    if ( ret_ftruncate == -1 ){
        perror("Erro em ftruncate\n");
        exit(1);
    }

    // Mapeia a regiao de memoria com a seu tamanho, modo de protecao e flags especificas
    ptr3 = ptr2 = ptr1 = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    if ( *ptr1 == -1 ){
        perror("Erro em mmap\n");
        exit(1);
    }

    /*****************************************************************************************/

    // Pegando o endereco da regiao como: struct item *
    struct item *pont1 = (struct item *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    if ( pont1 == MAP_FAILED ){
        perror("Erro em mmap\n");
        exit(1);
    }

 

    // Pq ptr2 recebe endereco de ptr1 + 100?
    // ptr2 = ptr1 + 100
    // AQUI ELE DEFINE UMA REGIAO DE MEMORIA PARA FUNCIONAR COMO UMA TRAVA
    // JA QUE NAO TEM COMO USAR UMA VARIAVEL GLOBAL ENTRE OS PROCESSOS
    // EH FEITO COM UMA PORCAO DA REGIAO DE MEMORIA
    
    // Definindo a ultima posicao da regiao de mem compart como a var compartilhada entre os processos
    ptr2 = ptr2 + tam_regiao - 1;
    *ptr2 = 0;

    printf("endereco inicial: %x\n", *ptr2);
    // Teste do vetor de posicao sequencial
    //int vet_int[3] = {0, 1, 2};
    //for (int i=0; i<8; i++){
    //    sprintf(ptr1, "%d ", vet_int[i]);
    //    ptr1 += sizeof(vet_int[i]);
    //}


    for (int i=0; i<10; i++){
        insere_lista(p1, i, pont1);
        pont1 += sizeof(struct item *); 
    } 

    imprime(p1);
    
    while( *ptr2 == 0 )
        ;

    
    *ptr2 = 0;
   

    remove_ebpf(caminho_prog, &bpf);
    return 0;
}
