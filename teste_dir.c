#include <stdio.h>
#include <stdlib.h>


int main(){

    const char *dir = getenv("SIGSHARED");
    printf("Caminho do diretorio do projeto: %s\n", dir);
}
