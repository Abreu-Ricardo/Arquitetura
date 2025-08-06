#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>


/**********************************************************/

void signal_handler(int signum, siginfo_t *info, void *context) {
    //if (signum == SIGUSR1) {
    if (signum == SIGRTMIN) {
        uint64_t num = (uint64_t)info->si_value.sival_ptr; // info->si_ptr;
        printf("Sinal recebido SIGRTMIN ptr: %ld \n", (long int)info->si_value.sival_ptr
        /*info->si_value.sival_int*/ /*si_value.sival_ptr*/ );
    }

}
/**********************************************************/

int main() {
    
    struct sigaction act;
    act.sa_flags = SA_SIGINFO;  // Permite recebimento de sinal com dados
    act.sa_sigaction = signal_handler;
    sigemptyset(&act.sa_mask);

    // Registra um handler para SIGUSR1
    //if (sigaction(SIGUSR1, &act, NULL) == -1) {
    if (sigaction(SIGRTMIN, &act, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    /**********************************************************/
    FILE *fp = popen("xclip -selection clipboard", "w");
    if (fp == NULL) {
        perror("popen failed");
        return 1;
    }
    int PID = getpid();
    char txt[10];

    // Poe o pid no clipboard ja
    sprintf(txt, "%d", PID);  // converte para string
    fprintf(fp , "%s", txt);
    pclose(fp);
    /**********************************************************/

    printf("Receiver comecou. PID: %d\n", PID);
    
    // Mantem o processo rodando para receber sinais
    while (1) {
        pause();  // Espera por sinais
    }

    return 0;
}
