#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>


typedef struct {
    int dia;
    int mes;
    int ano;

} data; 


void muda_valor(data *dado){
    
    dado->dia = 18;
    dado->mes = 12;
    dado->ano = 2024;

    
    printf("****** <Processo Pai> data: %d/%d/%d\n", dado->dia, dado->mes, dado->ano);

    while(1){
        ;
    }
    return;
}

void imprime(data *dado){
    
    dado->dia = 01;
    dado->mes = 01;
    dado->ano = 2025;

    printf("<Processo filho> data %d/%d/%d\n", dado->dia, dado->mes, dado->ano);
    
    while(1){
        ;
    }

    return;
}

int main()
{
	pid_t pid;
	int status;
    data hj;	



    /*****************************/
	/* cria outro processo */
	pid = fork();
	if (pid < 0) { /* ocorrência de erro*/
		fprintf(stderr, "Criação Falhou");
		exit(-1);
	}
	else if (pid == 0) { /* processo filho*/
        if (setsid() < 0)
            exit(-1);

        imprime(&hj);
		printf("==== Executando o processo filho (%d) ====\n", getpid());
		//execlp("/bin/ls", "/bin/ls", "-l", NULL);
	}
	else { /* processo pai */
        muda_valor(&hj);
		int i;
		/* pai irá esperar o filho completar
		   execução */
		printf("\n ***** Vai executar filho %d ****\n", pid);
		pid = wait (&status); //NULL);
		printf("\n ***** Filho (%d) Completou Execução e retornou %d\n", pid, status);
		exit(0);
	}
}

