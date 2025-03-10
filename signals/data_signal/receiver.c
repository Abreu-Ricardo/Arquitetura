#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void signal_handler(int signum, siginfo_t *info, void *context) {
    if (signum == SIGUSR1) {
        printf("Sinal recebido SIGUSR1 com dado: %d\n", info->si_value.sival_int);
    }
}

int main() {
    struct sigaction act;
    act.sa_flags = SA_SIGINFO;  // Permite recebimento de sinal com dados
    act.sa_sigaction = signal_handler;
    sigemptyset(&act.sa_mask);

    // Registra um handler para SIGUSR1
    if (sigaction(SIGUSR1, &act, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    printf("Receiver comecou. PID: %d\n", getpid());
    
    // Mantem o processo rodando para receber sinais
    while (1) {
        pause();  // Espera por sinais
    }

    return 0;
}
