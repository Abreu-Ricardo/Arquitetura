#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


#include "bib/teste_bib.h"


int main(int argc, char **argv){
	
	char caminho_prog[200];
	struct info_ebpf bpf;

	if (argc < 2){
		printf("Erro, passe o nome do arquivo.o\n");
		exit(1);
	}

	if (argc < 3){
		printf("Erro, passe o nome da funcao do prog ebpf\n");
		exit(1);
	}

	getcwd(caminho_prog, 200);
	strcat(caminho_prog, "/");
	strcat(caminho_prog, argv[1]);

	carrega_ebpf(caminho_prog, argv[2], &bpf);
	

	return 0;
}
