#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>


int cont_sin = 0;

void siguser(int signum){

    if (signum == 10){
        printf("Recebeu sinal SIGUSR1(%d): %d!\n", signum, ++cont_sin);
    }

    if (signum == 2){
        printf("Recebi um sinal de SIGINT(%d), ate mais...\n", signum);
        exit(1);
    }

    //cont_sin++;
}


int main(){

    // Capta sinal de SIGUSR1(valor 10)
    signal( SIGINT , siguser);
    signal( SIGUSR1, siguser);

    printf("Entrando no loop de espera...\nPID do processo: %d\n", getpid());

    while(1){
        ;
    }

    return 0;
}
