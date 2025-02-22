#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>


#include "signal_monitor.skel.h"


int main(int argc, char **argv){

    if (argc < 2){
        printf("Passe o PID do processo que receberá o sinal\n./envia_sinal <PID>\n");
        return 1;
    }

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    struct signal_monitor_bpf *skel;
    skel = signal_monitor_bpf__open_and_load();
    if (!skel){ 
        printf("Erro ao carregar programa\n"); 
        goto cleanup;
    }

    int ret_attach = signal_monitor_bpf__attach(skel);
    if(ret_attach < 0){ 
        printf("Erro ao aclopar programa eBPF\n");
        goto cleanup;
    }
    
    /***********************************************************/
    
    pid_t proc_alvo = atoi(argv[1]);
    int ret = kill(proc_alvo, 10);
    
    if (ret == 0){
            printf("Erro ao enviar sinal\n");
    }
    else{
        printf("Erro ao enviar sinal para %d\n", ret);
    }

    for(int i=0; i<100; i++){
        printf("Enviando(%d)...\n", i);
        if ( kill(proc_alvo, 10) < 0 ){
            printf("# Erro ao enviar sinal #\n");
        }
        usleep(100000);
    }

cleanup:
    signal_monitor_bpf__destroy(skel);
    return 0;
}
