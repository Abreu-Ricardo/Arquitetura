#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>


/**********************************************************/
int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Passar: %s <PID> <DADO>\n", argv[0]);
        return 1;
    }

    pid_t pid_alvo = atoi(argv[1]); // pega o PID do receiver
    int       dado = atoi(argv[2]); // Pega o dado para enviar p/ receiver

    uint64_t ptr = 1234567890;
    
    union sigval valor;
    //valor.sival_int = 1;  // Anexa dado ao sinal
    valor.sival_ptr = (void *)ptr;

    // Envia SIGUSR1 com dados
    //if (sigqueue(pid_alvo, SIGUSR1, valor) == -1) {
    if (sigqueue(pid_alvo, SIGRTMIN, valor) == -1) {
        perror("sigqueue");
        return 1;
    }

    //while(1){ pause(); }

    //printf("SIGUSR1 enviado para processo %d com dado %d\n", pid_alvo, dado);
    printf("SIGRTMIN enviado para processo %d com dado %d\n", pid_alvo, dado);
    return 0;
}

