#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

void send_signal(pid_t parent_pid) {
    //sleep(3);  // Simulate some work
    printf("Child: Sending SIGUSR1 to parent (PID: %d)\n", parent_pid);
    kill(parent_pid, SIGUSR1);
}

int main(int argc, char **argv) {
    if (argc < 2){
        printf("Passe o PID do proc alvo\n");
        return 1;
    }

    //pid_t pid = fork();

    printf("Iniciando...\n");

    for (int i = 0; i<10; i++){
        
        usleep(10);
        send_signal(atoi(argv[1]));
    }

    return 0;
}
