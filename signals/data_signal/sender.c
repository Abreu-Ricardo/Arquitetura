#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Passar: %s <PID> <DADO>\n", argv[0]);
        return 1;
    }

    pid_t pid_alvo = atoi(argv[1]); // pega o PID do receiver
    int dado = atoi(argv[2]);       // Pega o dado para enviar p/ receiver

    union sigval valor;
    valor.sival_int = dado;  // Anexa dado ao sinal

    // Envia SIGUSR1 com dados
    if (sigqueue(pid_alvo, SIGUSR1, valor) == -1) {
        perror("sigqueue");
        return 1;
    }

    printf("SIGUSR1 enviado para processo %d com dado %d\n", pid_alvo, dado);

    return 0;
}

