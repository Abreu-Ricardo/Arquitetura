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

struct xdp_program *prog_xdp = NULL;
struct bpf_object *bpf_ob;
struct info_ebpf bpf;

char *caminho_prog = "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/testes/xsk_kern.o"; 



// Para caso o programa consumidor der erro e o mapa nao ficar alocado
static void remove_xdp(){
    //getchar();
	xdp_program__detach(prog_xdp, 2, XDP_MODE_SKB, 0);
	xdp_program__close(prog_xdp);

    printf("\nPrograma Removido!\n");
	exit(0);
}


/***************************************************************************/
int main(int argc, char **argv){

    char *ptr1;
    int *ptr2;
    char *nome_regiao = "/memtest";
    int fd_shm;


    //carrega_ebpf(caminho_prog, "teste", &bpf);
    //atualiza_mapa(caminho_prog, "mapa_fd", nome_regiao, &bpf);
    //le_mapa(&bpf);


    // CARREGA PROGRAMA XDP
	//prog_xdp = xdp_program__open_file(caminho_prog, "xdp", NULL);
	//if (!prog_xdp) {
	//	printf("Erro ao abrir o programa xdp\n");
	//	return 1;
	//}

    //printf("nome do programa xdp:%s\n", xdp_program__name(prog_xdp));

	//int ret_attach = xdp_program__attach(prog_xdp, 2, XDP_MODE_SKB, 0);
    //printf("valor de ret_attach: %d\n", ret_attach);

    //if (ret_attach) {
	//	printf("Error, Set xdp fd on %d failed\n", 2);
	//	return ret_attach;
	//}

 	//bpf_ob = xdp_program__bpf_obj(prog_xdp);
	//
	//int mapa_fd = bpf_object__find_map_fd_by_name(bpf_ob, "mapa_fd"); 
	//if (mapa_fd < 0) {
	//	printf("Erro ao tentar obter o fd do mapa pelo bpf_obj, retorno: %d\n", mapa_fd);
    //    bpf_object__close(bpf_ob);
	//	return mapa_fd;
	//}
    // FIM CARREGA PROGRAMA XDP


    // Dados a serem escritos da mem compart
    const char *msg = "Oii, sou a msg";
    const char *msg1 = "\nOlaa, sou a msg2";

    char *caminho_prog = "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/testes/xsk_kernel.o";
    struct bpf_object *bpf_obj;
    struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, "mapa_fd");
    printf("Nome do mapa: %s\n", bpf_map__name(map));
    
    //atualiza_mapa();
    // Cria a regiao de mem. compart.
    // fd_shm = shm_open(nome_regiao, O_CREAT | O_RDWR, 0666);
    // if (fd_shm == -1){
    //     perror("Erro em shm_open\n");
    //     exit(1);
    // }

    printf("FSDFSDFSDF\n");
    //int key = 0;
    //char *valor;
    //int mapa_fd = bpf_obj_get("/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/codigo_proposta/Arquitetura/dados/mapa_fd");
    //int ret_look = bpf_map_lookup_elem(mapa_fd, &key, &valor);
    //printf("Nome do valor pego %s\n", valor);

    signal(SIGINT, remove_xdp);
    // Tamanho da regiao de mem.
    //int tam_regiao = 4096;
    uint64_t vetor[100];
    int tam_regiao = 500 * sizeof(vetor) + 1;

    // Atribuindo tamanho para a regiao de mem. compart.
   // int ret_ftruncate = ftruncate(fd_shm, tam_regiao);
   // if ( ret_ftruncate == -1 ){
   //     perror("Erro em ftruncate\n");
   //     exit(1);
   // }

   // // Mapeia a regiao de memoria com a seu tamanho, modo de protecao e flags especificas
   ptr1 = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
   ptr2 = (int *)  mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
   if ( *ptr1 == -1 ){
        perror("Erro em mmap\n");
        exit(1);
   }

   for (int i = 0; i<100; i++){
       printf("<consumidor>valor consumidor %d\n", *ptr2);
       ptr2 += sizeof(int *);
   }


    //ptr2 = ptr1 + 100;
    //*ptr2 = 0;
    // #3
    // #3
    // #3
    // #3

    // Escrita na regiao de mem compart
    //sprintf(ptr1, "%s", msg);
    //ptr1 += strlen(msg);
    //sprintf(ptr1, "%s", msg1);
    //ptr1 += strlen(msg1);
    //
    //while( *ptr2 == 0 )
    //    ;

    //*ptr2 = 0;
    //
    
    printf("Pressione Ctrl+C para remover...\n");
    while(1){
        ;
    }

    return 0;
}
