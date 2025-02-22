#include <stdio.h>
#include <signal.h>
#include <stdlib.h>


int cont_sin = 0;

void sigint(){
    printf("Recebi um sinal de sigint, ate mais...\n");
}

void siguser(){
    cont_sin++;
    printf("Recebeu sinal(%d)!\n", cont_sin);
}


int main(){

    // Capta sinal de SIGUSR1(valor 10)
    signal(10, siguser);
    //signal( 2, sigint);

    printf("Entrando no loop de espera...\n");

    while(1){
        ;
    }

    return 0;
}
