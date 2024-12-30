#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(){

    char *path_memtest     = "/dev/shm/memtest";
    char *path_trava       = "/dev/shm/trava";
    char *path_info_global = "/dev/shm/info_global";

    // Soh funciona com O_RDONLY
    printf("Valor do fd da memtest %10d\n", open(path_memtest, O_RDONLY));
    printf("Valor do fd da trava   %10d\n", open(path_trava, O_RDONLY));
    printf("Valor do fd da fo infor_global %2d\n", open(path_info_global, O_RDONLY));


    return 0;
}
