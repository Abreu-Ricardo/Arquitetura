#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <errno.h> // todos os retornos de erro ficam armazenados em errno

#include "teste_bib.h"


// PARA COMPILAR COM A LIB --> gcc ./bib/teste_bib.c load.c -lbpf -lxdp -o loader
// sudo ./loader espaco_kernel.o teste

struct bpf_map      *map; 
struct bpf_prog_info prog_info;
struct bpf_map_info map_info;
struct bpf_object   *bpf_obj;

__u32 info_len = sizeof(map_info);

/**********************************************************************************************************/

// Essa funcao vai carregar o programa e salvar as informacoes na struct passada
void carrega_ebpf(char *caminho_prog, char *nome_prog, struct info_ebpf *infos){
    // Caminho para o arquivo objeto que contém o programa eBPF
    const char *bpf_prog_file = caminho_prog;  // Arquivo pré-compilado com clang
    const char *prog_name = nome_prog;   // Nome do programa eBPF dentro do arquivo .o

    //struct bpf_map *map; 
    //struct bpf_map_info map_info;
    //struct bpf_object *bpf_obj;
    __u32 info_len = sizeof(map_info);
    __u32 key =0, valor;

    // Passo 1: Carregar o arquivo objeto do eBPF
    bpf_obj = bpf_object__open_file(caminho_prog, NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Erro ao abrir arquivo BPF: %s\n", strerror(errno));
        exit (1);
    }

    // Passo 2: Carregar o programa eBPF para a memória do kernel
    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "Erro ao carregar programa BPF: %s\n", strerror(errno));
        bpf_object__close(bpf_obj);
        exit (1);
    }

    // Passo 3: Obter o descritor do programa eBPF
    infos->prog_fd = bpf_program__fd(bpf_object__find_program_by_name(bpf_obj, nome_prog));

    if (infos->prog_fd < 0) {
        fprintf(stderr, "Erro ao obter descritor do programa BPF: %s\n", strerror(errno));
        bpf_object__close(bpf_obj);
        exit (1);
    }

    __u32 prog_info_len = sizeof(prog_info);
   
    int ret_prog_info = bpf_obj_get_info_by_fd(infos->prog_fd, &prog_info, &prog_info_len);
    printf("\n<ID do programa: %d>\n", prog_info.id);


    printf("<Programa eBPF carregado com sucesso! FD do programa: %d>\n", infos->prog_fd);
}

/**********************************************************************************************************/
int remove_ebpf(char caminho_prog[], struct info_ebpf *infos){
    
    struct bpf_object *bpf_obj = bpf_object__open_file(caminho_prog, NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Erro ao buscar o arquivo BPF para fechar: %s\n", strerror(errno));
        exit (1);
    }

    // Passo 4: Fazer algo com o programa eBPF, por exemplo, anexar a um gancho (hook).
    // Para este exemplo, o programa será carregado, mas não anexado a um hook específico.

    // Simulação de uma espera (substitua por alguma lógica específica, se necessário)
    printf("\nPressione ENTER para remover o programa eBPF...\n");
    getchar();

    // Passo 5: Remover o programa eBPF da memória (fechar o descritor)
    if (close(infos->prog_fd) < 0) {
        fprintf(stderr, "Erro ao fechar o descritor do programa BPF: %s\n", strerror(errno));
        bpf_object__close(bpf_obj);
        return 1;
    }

    // Fechar a estrutura do objeto BPF
    bpf_object__close(bpf_obj);
    printf("\n\nPrograma eBPF removido com sucesso.\n");


    return 0;
}

/**********************************************************************************************************/

int le_mapa(struct info_ebpf *infos){
    
    int key=0, temp; 
    int ret_map_info;
   
    map = bpf_object__find_map_by_name(bpf_obj, "mapa_fd");
    infos->mapa_fd = bpf_map__fd(map);

    ret_map_info = bpf_obj_get_info_by_fd( infos->mapa_fd, &map_info, &info_len);
    bpf_map_lookup_elem(infos->mapa_fd, &key, &temp);
    
    printf("\n\n<FD do mapa:    %d>\n", infos->mapa_fd);
    printf("<ID do mapa:    %d>\n", map_info.id);
    printf("<Nome do mapa:  %s>\n", bpf_map__name(map));
    printf("<Valor do mapa: %d>\n", temp);


    return 0;
}

/**********************************************************************************************************/

int atualiza_mapa( char caminho_prog[], char nome_mapa[], __u32 *valor, struct info_ebpf *infos){
    
    //struct bpf_map *map;
    //struct bpf_map_info map_info;
    //struct bpf_object *bpf_obj;
    
    int temp, key=0;
    
    //__u32 info_len = sizeof(map_info);

    //bpf_obj= bpf_object__open_file(caminho_prog, NULL);
    
    // Pegar o FD do mapa
    //map = bpf_object__find_map_by_name(bpf_obj, "mapa_fd");
    //infos->mapa_fd = bpf_map__fd(map);
    //
    //int ret_map_info = bpf_obj_get_info_by_fd( infos->prog_fd, &map_info, &info_len);
    //
    //
    //bpf_map_lookup_elem(infos->mapa_fd, &key, &temp);
    //
    //printf("<FD do mapa:    %d>\n", infos->mapa_fd);
    //printf("<ID do mapa:    %d>\n", map_info.id);
    //printf("<Nome do mapa:  %s>\n", bpf_map__name(map));
    //printf("<Valor do mapa: %d>\n", temp);

    int erro_map_update = bpf_map_update_elem( infos->mapa_fd, &key, valor, BPF_EXIST );

    bpf_map_lookup_elem(infos->mapa_fd, &key, &temp);
    printf("<Novo valor do mapa: %d>\n", temp);

    return 0;
}

/***********************************************************************************************************/


// Template criado para teste, usar como esqueleto
/*
int main(int argc, char **argv) {
    // Caminho para o arquivo objeto que contém o programa eBPF
    const char *bpf_prog_file = "espaco_kernel.o";  // Arquivo pré-compilado com clang
    const char *prog_name = "teste";   // Nome do programa eBPF dentro do arquivo .o

    struct bpf_object *bpf_obj;
    int prog_fd;

    // Passo 1: Carregar o arquivo objeto do eBPF
    bpf_obj = bpf_object__open_file(bpf_prog_file, NULL);
    if (libbpf_get_error(bpf_obj)) {
        fprintf(stderr, "Erro ao abrir arquivo BPF: %s\n", strerror(errno));
        return 1;
    }

    // Passo 2: Carregar o programa eBPF para a memória do kernel
    if (bpf_object__load(bpf_obj)) {
        fprintf(stderr, "Erro ao carregar programa BPF: %s\n", strerror(errno));
        bpf_object__close(bpf_obj);
        return 1;
    }

    // Passo 3: Obter o descritor do programa eBPF
    prog_fd = bpf_program__fd(bpf_object__find_program_by_name(bpf_obj, prog_name));
    if (prog_fd < 0) {
        fprintf(stderr, "Erro ao obter descritor do programa BPF: %s\n", strerror(errno));
        bpf_object__close(bpf_obj);
        return 1;
    }

    printf("Programa eBPF carregado com sucesso! FD: %d\n", prog_fd);

    // Pegar o FD do mapa
    struct bpf_map *map; 
    map = bpf_object__find_map_by_name(bpf_obj, "mapa_fd");
    int fd_do_map = bpf_map__fd(map);
    
    printf("-->FD do mapa: %d\n", fd_do_map);

    struct bpf_map_info map_info;
    __u32 info_len = sizeof(map_info);
    
    int ret_info = bpf_obj_get_info_by_fd( fd_do_map, &map_info, &info_len);

    printf("-->ID do mapa: %d\n", map_info.id);

    __u32 key =0, valor;
    bpf_map_lookup_elem(fd_do_map, &key, &valor);
    printf("valor do mapa: %d\n", valor);

    valor = 69;
    int erro_map_update = bpf_map_update_elem( fd_do_map, &key, &valor , BPF_EXIST);

    bpf_map_lookup_elem(fd_do_map, &key, &valor);
    printf("valor do mapa: %d\n", valor);



    // Passo 4: Fazer algo com o programa eBPF, por exemplo, anexar a um gancho (hook).
    // Para este exemplo, o programa será carregado, mas não anexado a um hook específico.

    // Simulação de uma espera (substitua por alguma lógica específica, se necessário)
    printf("Pressione ENTER para remover o programa eBPF...\n");
    getchar();

    // Passo 5: Remover o programa eBPF da memória (fechar o descritor)
    if (close(prog_fd) < 0) {
        fprintf(stderr, "Erro ao fechar o descritor do programa BPF: %s\n", strerror(errno));
        bpf_object__close(bpf_obj);
        return 1;
    }

    // Fechar a estrutura do objeto BPF
    bpf_object__close(bpf_obj);

    printf("Programa eBPF removido com sucesso.\n");

    return 0;
}
*/
