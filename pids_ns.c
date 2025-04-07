#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>



/* Esse programa compara os processos
 * que sao filhos do processo passado,
 * no caso eh preciso passar o proceso
 * bash do container isolado e a partir 
 * dai podemos ver quem eh filho do bash
 * nesse container, portanto, esta executando
 * dentro do container
 */


int main(int argc, char **argv){

    char *path_proc = "/proc/";
    char path_alvo[300];
    DIR  *proc;
    
    FILE *data_file;
    int fd_file;
    
    struct dirent *data_proc;

    if (argc < 2){
        printf("Passe o PID: %s <PID>\n", argv[0]);
        goto erro;
    }

    proc = opendir(path_proc);
    if ( proc == NULL){
        perror("Erro ao abri o diretorio");
        goto erro;
    }

    char pid[256], nome[256], estado[256], ppid[256];
    
    struct dirent *actual_dir;
    while( (actual_dir = readdir(proc)) ){ 
        // Verifica se o nome do dir atual eh um numero(processo) e se eh maior que o pid do NS
        if ( isdigit(*actual_dir->d_name)  && atoi(actual_dir->d_name) >= atoi(argv[1])){
           
            sprintf(path_alvo, "/proc/%s/stat" , actual_dir->d_name);
            //printf("%s\n", path_alvo/*actual_dir->d_name*/);
            
            data_file = fopen( path_alvo , "r");
            if (data_file == NULL){
                perror("Erro ao abrir o diretorio");
                goto erro;
            }
            
            fscanf(data_file, "%s %s %s %s", pid, nome, estado, ppid);

            // Comparar se o PID do pai do processo eh igual ao pid do bash do NS
            if ( atoi(ppid) == atoi(argv[1])){
                printf("Processo:%d(%s) eh filho de:%d\n", atoi(actual_dir->d_name), nome ,  atoi(argv[1]));
            }
        }
    }
    
erro:
    return 1;

	return 0;
}
