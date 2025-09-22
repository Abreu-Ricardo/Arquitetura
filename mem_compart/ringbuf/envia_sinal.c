#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>


#include "shm_test.h"
//#include "signal_monitor.skel.h"

int long long start;
int long long end;

long long int cont_sinal  = 0;

/******************************************************************************************/
void handle(int signum){

    printf("Sinais enviados: %lld\n", cont_sinal);
    exit(0);
}

/******************************************************************************************/
static __always_inline volatile long long RDTSC() {
    
    //register long long TSC asm("eax");
    //asm volatile (".byte 15, 49" : : : "eax", "edx");
    //return TSC;

    unsigned int lo, hi;
    
    asm ("rdtsc" : "=a" (lo), "=d" (hi));         // Execute RDTSC and store results
    return ((long long)hi << 32) | lo;            // Combine high and low parts
}

/******************************************************************************************/
float media(long long int *ciclosV, int tam){

    float result = 0.0;

    for (int i=1; i < tam; i++){
        result += ciclosV[i];
    }
    result = result / tam;

    return result;
}

/*****************************************************************************************/
//void clean(struct signal_monitor_bpf *skel){
//    signal_monitor_bpf__destroy(skel);
//}

/*****************************************************************************************/
int main(int argc, char **argv){

    if (argc < 2){
        printf("Passe o PID do processo que receberá o sinal\n%s <PID> <num_signals>\n", argv[0]);
        return 1;
    }

    if (argc < 3){
        printf("Passe o PID e a quantidade de sinais para enviar\n%s <PID> <num_signals>\n", argv[0]);
        return 1;
    }

    signal(SIGINT, handle);

    pid_t pid = getpid();
    char settar_cpuf[30];
    
    printf("Atribuindo processo para a CPU 3...\n");
    sprintf(settar_cpuf, "taskset -cp 3 %d", pid);
    system(settar_cpuf);


    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

   // struct signal_monitor_bpf *skel;
   // skel = signal_monitor_bpf__open_and_load();
   // if (!skel){ 
   //     printf("Erro ao carregar programa\n"); 
   //     goto cleanup;
   // }

   // int ret_attach = signal_monitor_bpf__attach(skel);
   // if(ret_attach < 0){ 
   //     printf("Erro ao aclopar programa eBPF\n");
   //     goto cleanup;
   // }
   
    /***********************************************************/
    
    pid_t proc_alvo = atoi(argv[1]);
    int num_signals = atoi(argv[2]);

    int i = 0; 
    //long long int total_ciclos[num_signals], ciclos;
    long long int *total_ciclos, ciclos;
    total_ciclos = (long long int *) malloc( sizeof(long long int) * num_signals);

    struct timespec remaining, request = { 0,1 };
    union sigval sig_struct;
    uint64_t dados = 1234567890;
    sig_struct.sival_ptr = (void *)dados;

    int j = 0;
    start = RDTSC();
    for(i=0; i < num_signals/*100*/ ; i++){
        printf("Enviando(%d)...\n", i);
        //kill(proc_alvo, 10);

        //if ( kill(proc_alvo, SIGRTMIN+1) < 0 ){
        //    printf("# Erro ao enviar sinal #\n");
        //    exit(1);
        //}

        //start = RDTSC();
        if ( sigqueue(proc_alvo, SIGRTMIN+1, sig_struct) < 0 ){
            printf("# Erro ao enviar sinal #\n");
            exit(1);
        }
        //end = RDTSC();

        // 10000 --> 5us
        //start = RDTSC();
        usleep(800);
        //for(j = 0; j < 200000; j++){ ; }
        //end = RDTSC();

        //cont_sinal++;        
        //ciclos = end - start;
        //total_ciclos[i] = ciclos;
        //start = RDTSC();
        //printf("\n###\n");
        //end = RDTSC();
        //ciclos = end - start;
        //printf("\n### Ciclos gastos pelo sinal(%d): %lf ###\n", i, (double)ciclos/3600 );
        //usleep(1);
        //nanosleep(&request, &remaining);
    }
    end = RDTSC();
    ciclos = end - start;

    printf("Tempo de envio dos sinais em us: %lf\n", (double)ciclos/360000);
    printf("\n### Sinais enviados(%lld) ###\n", cont_sinal);
    //printf("Media dos ciclos gastos pelos sinais: %f\n", media(total_ciclos, num_signals));

cleanup:
    //clean(skel);
    return 0;

}
