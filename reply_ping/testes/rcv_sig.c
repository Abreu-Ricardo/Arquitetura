#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>



int main() {
    sigset_t set;
    pid_t pid = getpid();
    int sig=10;

    printf("Iniciando...\nPID: %d\n", pid);
    
    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGUSR1);            // Atribui o sinal SIGUSR1 para conjunto de sinais q ode "ouvir"
    sigprocmask(SIG_BLOCK, &set, NULL);  // Aplica o conjunto q pode "ouvir"
    
    printf("Esperando pelo sinal SIGUSR1...\n");

    int ret_sigwait;
    
    for (int i = 0; i < 10; i++){
    
        ret_sigwait= sigwait(&set, &sig);
        
        if ( ret_sigwait == 0 ){  // Wait for SIGUSR1
            printf("Sinal recebido SIGUSR1\n");
            //return 0;
        }
        else{
            printf("Erro ao receber o sinal: %d\n", ret_sigwait);
        }
    }

     sigwait(&set, &sig);
     printf("Ultimo sinal recebido\n");

    //while(1){ ;}

    return 0;
}

