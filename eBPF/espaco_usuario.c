/*** CODIGO PRECISA SER EXECUTADO COM SUDO ***/
/*** Compilacao: gcc espaco_usuario.c -lbpf -lxdp ***/
/*** Execucao: sudo ./a.out  ***/
/*** -lbpf para incluir biblioteca libbpf ***/
/*** -lxdp para incluir biblioteca libxdp ***/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <errno.h> // todos os retornos de erro ficam armazenados em errno
		           // strerror() pega esse valor e imprime a descricao do erro correspondente

#define TAM_STR 500


/***************************************************************************************/
int main(){
	char *read = "read";
	char *write = "write";
	int parametro_passado;

	// ATENCAO CUIDAR COMO NOME DO ARQUIVO OBJETO PASSADO, EH A PARTIR DELE QUE CONSTROI A struct bpf_object
	char *nome_programa = "espaco_kernel.o";
	char program_path[TAM_STR];
	char caminho_programa_completo[TAM_STR];
	// char *program_path = "/home/ricardo/Documents/Mestrado/Projeto-Mestrado/Projeto_eBPF/codigos_eBPF/testes/user_kernel/escrevemap_kernel.o";
	
	char *iface = "eno1";
	char *mapa_prog = "mapa_fd";
	char *mapa_hash = "mapa_hash";
    char *nome_prog_mapa = "teste/mapa_fd";

    char *caminho_teste = "/sys/fs/bpf/mapa_fd/mapa_fd";
	
    char pin_map_path[TAM_STR] = "/sys/fs/bpf";
	char caminho_mapa_completo[TAM_STR];
	char *nome_func = "teste";

	int key =0;
	int map_mem_fd, map_mem_fd2;
	int erro_map_update, erro_map_lookup;

	struct bpf_map	   *map;
	struct bpf_object  *programa_obj;
	struct bpf_program *programa_bpf;
	struct bpf_map_info mapa_info = {0};

	__u32 info_len = sizeof(mapa_info);
	__u64 value;
	__u32 valor = 0;

	/*** Verificacao dos parametros passados, se menor 2 n foi passado uma opcao  ***/
/*
    if (argc < 2){
		printf("Passe o parâmetro: write ou read na execução\n");
		return 1;
	}

	if(strcmp(argv[1], read) == 0){
		parametro_passado = 1;
	}	

	// Se argumento passado for write 
	else if (strcmp(argv[1], write) == 0){
		parametro_passado = 2;

	}

	// Se o argumento passado n for compativel
	else{
		printf("Passe o parâmetro: write ou read na execução\n");
		return 1;

	}
*/
	// Busca o caminho absoluto para o diretorio atual 
	getcwd(program_path, TAM_STR);


	// Concatena o caminho para o bpffs(bpf file system) com o nome do mapa 
	//snprintf(caminho_mapa_completo, TAM_STR, "%s/%s", pin_map_path, mapa_prog);
	snprintf(caminho_mapa_completo, TAM_STR, "%s/%s", pin_map_path, mapa_prog/*nome_prog_mapa*/);
	printf("-----> %s\n", caminho_mapa_completo);

   /* // Concatena o caminho para o bpffs(bpf file system) com o nome do mapa 
	snprintf(caminho_mapa_completo, TAM_STR, "%s/%s", pin_map_path, mapa_hash);
	printf("-----> %s\n", caminho_mapa_completo);
   */

	// Concatena o caminho para o o diretorio atual com o nome do programa
	snprintf(caminho_programa_completo, TAM_STR, "%s/%s", program_path, nome_programa);
	printf("-----> %s\n", caminho_programa_completo);

	// Passo 1:
	// Passa o caminho para o arquivo compilado, para ter a struct bpf_object 
	programa_obj = bpf_object__open_file(caminho_programa_completo, NULL);
	if (programa_obj == NULL){
		printf("\nPasso 1: bpf_object__open_file retornou NULL\n");
        return 1;
	}


    //printf("##### %x\n", *programa_obj);

	/**********************************************************************************************************************/


	// Passo 2:
	//  Primeiro parametro eh uma struct bpf_object preenchida e o segundo eh o nome da funcao do programa no kernel
	//  o retorno eh uma struct bpf_program com um monte de info 
	programa_bpf = bpf_object__find_program_by_name(programa_obj, nome_func);
	
	// Verifica se conseguiu achar o programa
	(programa_bpf == NULL)? printf("\nPasso 2: ERRO--> %s\n", strerror(errno)) : printf("\nPasso 2: nome do programa --> %s\n", bpf_program__name(programa_bpf));


	/**********************************************************************************************************************/


	// Passo 3:	
	// Buscar o mapa para preencher a struct bpf_map 
	map = bpf_object__find_map_by_name(programa_obj, mapa_prog);
	map == NULL? perror("\nPasso 3, erro ao buscar mapa") : printf("\nPasso 3: achou mapa --> %s\n",bpf_map__name(map));

	// Retorna o fd(file descriptor) obtido pela struct bpf_map
	map_mem_fd = bpf_map__fd(map);
	
    if (map_mem_fd < 0){
        printf("\nErro em bpf_map__get, retorno --> %d: %s\n", map_mem_fd,strerror(errno));
    
    }else{
        printf("Achou fd do mapa --> %d\n", map_mem_fd);
    }
    

    int temp = bpf_object__find_map_fd_by_name(programa_obj, "mapa_fd");
    if (temp < 0){
        perror("ERRO em find_map_fd_by_name");
    }else{
        printf("valor de temp %d\n", temp);
    }


	/**********************************************************************************************************************/

	// MAPA JA PINADO COM xdp-loader --pin-path e com atributo dentro do mapa
	//int ret_pin_path = bpf_map__set_pin_path(map_fd, map_path);
	//if (ret_pin_path < 0) printf("erro ao atrribuir caminho para pin do mapa\n");
	//printf("pin path--> %s\n", bpf_map__pin_path(map_fd));
		// Tentando pinar o mapa
	//int ret =  bpf_object__pin_maps(programa_obj, map_path);
	//int ret =  bpf_map__pin(map_fd, NULL);
	//if (ret < 0) printf("bpf_map__pin retornou erro\n");
	//printf("esta pinado ? r= %s\n", bpf_map__is_pinned(map_fd)? "true" : "false");

	/**********************************************************************************************************************/


	// Verifica se foi possivel encontrar o mapa 
	// Usa esse fd nas helpers functions, pq ele pega o mapa ja pinado em /sys/fs/bpf/mapa_fd 
	map_mem_fd2 = bpf_obj_get(/*caminho_mapa_completo*/ caminho_teste);
	if (map_mem_fd2 < 0){
        perror("Erro ao buscar fd2 do mapa");
    }else{
        printf("Achou fd2 do mapa --> %d\n", map_mem_fd2);
    }


	// Constroi a struct que vai usar para pegar as infos do mapa 
	// definicao aqui --> https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/bpf.h#L6470 
	int ret_info = bpf_obj_get_info_by_fd(map_mem_fd2, &mapa_info, &info_len);

	printf("\nValor de ret_info= %d  || errno--> %s\n", ret_info, strerror(errno));
	printf("id do mapa: %d\n", mapa_info.id);


	/**********************************************************************************************************************/


	//erro_map_update = bpf_map__update_elem( map, &key, sizeof(key), &valor, sizeof(valor), BPF_EXIST);
    bpf_map_lookup_elem(map_mem_fd2, &key, &valor);
    printf("valor do mapa: %d\n", valor);
   
    valor = (__u32)0;
    erro_map_update = bpf_map_update_elem( map_mem_fd2, &key, &valor, BPF_EXIST);
    printf("retorno do update: %d\n", erro_map_update);


	//printf("valor do mapa--> %d || erro_map_lookup--> %d\n", value, erro_map_lookup);
	
	return 0;
}
