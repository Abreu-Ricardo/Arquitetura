#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <errno.h>


/**********************************************************/

//void signal_handler(int signum, siginfo_t *info, void *context) {
void signal_handler(int signum, struct signalfd_siginfo *info, void *context) {
    //if (signum == SIGUSR1) {
    if (signum == SIGRTMIN+1) {
        //uint64_t num = (uint64_t)info->si_value.sival_ptr; // info->si_ptr;
        //uint64_t num = (uint64_t)info->ssi_ptr;
        //printf("Sinal recebido SIGRTMIN+1 ptr: %ld \n", (long int)info->ssi_ptr
        ///*info->si_value.sival_int*/ /*si_value.sival_ptr*/ );
    }

}
/**********************************************************/

int main() {

    pid_t pid = getpid();
    char settar_cpuf[30];
    
    printf("Atribuindo processo para a CPU 4...\n");
    sprintf(settar_cpuf, "taskset -cp 4 %d", pid);
    system(settar_cpuf);


    //struct sigaction act;
    //act.sa_flags = SA_SIGINFO;  // Permite recebimento de sinal com dados
    //act.sa_sigaction = signal_handler;
    //sigemptyset(&act.sa_mask);

    //// Registra um handler para SIGUSR1
    ////if (sigaction(SIGUSR1, &act, NULL) == -1) {
    //if (sigaction(SIGRTMIN, &act, NULL) == -1) {
    //    perror("sigaction");
    //    exit(1);
    //}

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
    siginfo_t recv;
    sigset_t set; 
    
    sigemptyset(&set);                    // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGRTMIN+1);          // Atribui o sinal SIGUSR1 para conjunto de sinais q ode "ouvir"
    sigprocmask(SIG_BLOCK, &set, NULL);   // Aplica o conjunto q pode "ouvir"

    int ret_sig = 0;
    int sigrtmin1 = SIGRTMIN+1;


    // Cria um file descriptor para o kernel escrever o sinal nele
    // assim evitando que o kernel tenha que acordar o processo o 
    // tempo todo
    int sigfd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sigfd < 0) {
        perror("signalfd");
        exit(1);
    }

    /***** EPOLL *****/
    // Criando um fd para fazer epoll 
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1");
        exit(1);
    }

    struct epoll_event ev;
    ev.events = EPOLLIN; // The associated file is available for read(2) operations.
    ev.data.fd = sigfd;

    // Atribuindo o fd do sinal na lista de interesse
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev) < 0) {
        perror("epoll_ctl");
        exit(1);
    }
    /***** *****/

    /***** RECEBIMENTO DO SINAL COM EPOLL NO FD DO SINAL *****/
    while (1) {
        struct epoll_event events[UINT8_MAX];
        int n = epoll_wait(epfd, events, 8, -1);  // -1 = block indefinitely
        
        if (n < 0) {
            if (errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == sigfd) {
                struct signalfd_siginfo si;
                ssize_t res = read(sigfd, &si, sizeof(si));
                if (res != sizeof(si)) {
                    perror("read(signalfd)");
                    continue;
                }

                //printf("Received signal %d from PID %d | data: %ld\n", si.ssi_signo, si.ssi_pid, (uint64_t)si.ssi_ptr);
                signal_handler(35, &si, NULL);

                if ( si.ssi_signo == SIGTERM || si.ssi_signo == SIGINT)
                    goto done;
            }
        }
    }

done:
    close(sigfd);
    close(epfd);


    // Mantem o processo rodando para receber sinais
    //while( sigwaitinfo(&set, &recv)  > 0 ){

    //    printf("RECEBEU SINAL\n");
    //    ret_sig = 35;
    //    signal_handler(ret_sig, &recv, NULL);
    //}

    return 0;
}
