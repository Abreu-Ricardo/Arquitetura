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



 typedef struct data{
    char dados[1500];
}buf_dados;

/****************************************************/
int main(int argc, char **argv){

    // Tamanho e nome da regiao de mem
    const int tam_regiao = 800 * sizeof (buf_dados ) + 1;
    const char nome_regiao[50];

    // descritor e ponterios para a mem
    int fd_shm;
    char *ptr1, *ptr2;

    struct info_ebpf bpf;
    char *caminho_prog = "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/espaco_kernel.o";


    struct bpf_object *bpf_obj;
    struct bpf_map *map;
/*
    bpf_obj = bpf_object__open_file(caminho_prog, NULL);
    if (bpf_obj == NULL){
        printf("ERRO AO ABRIR ARQUIVO\n");
        bpf_object__close(bpf_obj);
        return -1;
    }

    
    map = bpf_object__find_map_by_name(bpf_obj, "mapa_fd");
    if (map == NULL){
        printf("ERRO AO ABRIR MAPA\n");
        bpf_object__close(bpf_obj);
        return -1;
    }

    printf("Nome do mapa: %s\n", bpf_map__name(map));
    printf("FD do mapa:   %d\n", bpf_map__fd(map));


    //int mapa_fd = bpf_map__fd(map);
    //int mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "mapa_fd");
*/

    // ### Primeiro caminho eh para rodar no espaco de usuario normal, o segundo eh para rodar entre containers ###
    //int mapa_fd = bpf_obj_get("/sys/fs/bpf/mapa_fd");
    int mapa_fd = bpf_obj_get("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_fd");
    if (mapa_fd < 0){
        printf("<consumidor>Erro ao obter o FD do mapa\n");
        //bpf_object__close(bpf_obj);
        return -1;
    }


    //struct bpf_program *programa_bpf;
    //programa_bpf = bpf_object__find_program_by_name(bpf_obj, "teste");


    //carrega_ebpf(caminho_prog, "teste", &bpf);

    int key=0;
    char temp[50];

    int ret_lookup = bpf_map_lookup_elem(mapa_fd, &key, (void *)nome_regiao);
   
    printf("\n<consumidor>nome da regiao: %s\n\n", nome_regiao);

    // Passo 1, pegar o fd local da regiao de mem compart
    // bit mask, segundo a definicao de sys/stat.h 
    // 0666 --> S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
    fd_shm = shm_open(nome_regiao, O_RDWR, 0666);
    printf("valor do fd_shm em consumidor: %d\n", fd_shm);

    // Passo 2, mapear o codigo para o espaco de mem do processo
    ptr2 = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    
    struct data *p = (struct data *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);


    for(int i=0; i < 100; i++){
        //printf("%d %s\n", i, p->dados);
        
        // Salva dados na estrutura
        //sprintf(vetor[i].dados, "Valor escrito por produtor %d\n", i);
        //printf("%s", vetor[i].dados);
    

        // Copiar os dados da estrutura para a memoria compart.
        //memcpy(p, &vetor[i], sizeof( buf_dados) );
        //printf("Conferindo endereco: %p %s", p, p->dados );

       printf("<consumidor>: %s", (char *) p->dados); 
        // Anda o ponteiro para a prox posicao 
        p = p + sizeof(struct data *);
    }




    ptr2 = ptr2 + tam_regiao - 1;
    printf("%s\n", (char *) ptr2);

    *ptr2 = 1;


    while(*ptr2 == 1)
        ;


    shm_unlink(nome_regiao);

    return 0;
}
