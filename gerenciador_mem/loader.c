#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "bib/teste_bib.h"


int main(int argc, char **argv){
	
	char caminho_prog[200];
    char *nome_mapa = "mapa_fd";
    __u32 valor = 2424;

	struct info_ebpf bpf;

	if (argc < 2){
		printf("Erro, passe o nome do arquivo.o\n");
		exit(1);
	}

	if (argc < 3){
		printf("Erro, passe o nome da funcao do prog ebpf\n");
		exit(1);
	}

    // Pega dir atual e salva num buffer, 200 eh o max de char que armazena
	getcwd(caminho_prog, 200);
    // Adiciona o / para pegar o arquivo no diretorio atual
	strcat(caminho_prog, "/");
    // Concantena o arquivo .o passado no caminho total
	strcat(caminho_prog, argv[1]);


	carrega_ebpf(caminho_prog, argv[2], &bpf);
    le_mapa(&bpf);
    
    atualiza_mapa(caminho_prog, nome_mapa, &valor, &bpf);
    //le_mapa(&bpf);
    remove_ebpf(caminho_prog, &bpf);
	

	return 0;
}
