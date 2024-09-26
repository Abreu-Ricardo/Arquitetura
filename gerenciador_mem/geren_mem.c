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


int main(int argc, char **argv){

    char *ptr1, *ptr2;
    char *nome_regiao = "/memcompart";
    int fd_shm;

    // Dados a serem escritos da mem compart
    const char *msg = "Oii, sou a msg";
    const char *msg1 = "Olaa, sou a msg2";

    // Cria a regiao de mem. compart.
    fd_shm = shm_open(nome_regiao, O_CREAT | O_RDWR, 0666);
    if (fd_shm == -1){
        perror("Erro em shm_open\n");
        exit(1);
    }

    // Tamanho da regiao de mem.
    int tam_regiao = 4096;

    // Atibuindo tamanho para a regiao de mem. compart.
    int ret_ftruncate = ftruncate(fd_shm, tam_regiao);
    if ( ret_ftruncate == -1 ){
        perror("Erro em ftruncate\n");
        exit(1);
    }

    // Mapeia o a regiao de memoria com a seu tamanho, modo de protecao e flags especificas
    ptr2 = ptr1 = (char *) mmap(0, tam_regiao, PROT_WRITE, MAP_SHARED, fd_shm, 0);
    if ( *ptr1 == -1 ){
        perror("Erro em mmap\n");
        exit(1);
    }


    ptr2 = ptr1 + 100;
    *ptr2 = 0;

    // Escrita na regiao de mem compart
    sprintf(ptr1, "%s", msg);
    ptr1 += strlen(msg);
    sprintf(ptr1, "%s", msg1);
    ptr1 += strlen(msg1);
    
    while( *ptr2 == 0 )
        ;

    *ptr2 = 0;
    
    return 0;
}
