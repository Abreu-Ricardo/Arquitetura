#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>


#include "minha_lib.h"

int main(int argc, char **argv){

    // Tamanho e nome da regiao de mem
    const int tam_regiao = 4096;
    const char *nome_regiao = "/memcompart";

    // descritor e ponterios para a mem
    int fd_shm;
    char *ptr1, *ptr2;
    
    // Passo 1, pegar o fd local da regiao de mem compart
    // bit mask, segundo a definicao de sys/stat.h 
    // 0666 --> S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
    fd_shm = shm_open(nome_regiao, O_RDWR, 0666);
    printf("valor do fd_shm em consumidor: %d\n", fd_shm);

    // Passo 2, mapear o codigo para o espaco de mem do processo
    ptr1 = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    printf("$$$ passou mmap %s\n", ptr1);

    ptr2 = ptr1 + 100;
    printf("%s\n", (char *) ptr1);

    *ptr2 = 1;


    while(*ptr2 == 1)
        ;


    shm_unlink(nome_regiao);

    return 0;
}
