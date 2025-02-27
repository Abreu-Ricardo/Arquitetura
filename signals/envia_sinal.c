#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>

#include "signal_monitor.skel.h"

int long long start;
int long long end;

static __always_inline volatile long long RDTSC() {
    
    //register long long TSC asm("eax");
    //asm volatile (".byte 15, 49" : : : "eax", "edx");
    //return TSC;

    unsigned int lo, hi;
    
    asm ("rdtsc" : "=a" (lo), "=d" (hi));         // Execute RDTSC and store results
    return ((long long)hi << 32) | lo;            // Combine high and low parts
} 

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
    //pid_t proc_alvo = 159297;
    //int ret = kill(proc_alvo, 10);
    
    //if (ret == 0){ printf("Enviando sinal...\n");}
    //else{ printf("Erro ao enviar sinal para %d\n", ret);}

    pid_t pid = getpid();
    char settar_cpuf[30];
    
    printf("Atribuindo processo para a CPU 5...\n");
    sprintf(settar_cpuf, "taskset -cp 5 %d", pid);
    system(settar_cpuf);

    int i = 0; 
    start = RDTSC();

    for(i=0; i < 1000; i++){
        //printf("Enviando(%d)...\n", i);
        //kill(proc_alvo, 10);
        if ( kill(proc_alvo, 10) < 0 ){
            printf("# Erro ao enviar sinal #\n");
        }
        //usleep(1);
    }
    end = RDTSC();

    printf("\n### Valor final de RDTSC %lld ###\n", end - start);

    //while(1){ int i = i * 1;}

cleanup:
    signal_monitor_bpf__destroy(skel);
    return 0;
}
