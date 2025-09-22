#include "shm_test.h"
#include <time.h>  

struct sigshared_ringbuffer *ringbuff;
void *mempool = NULL;

//uint64_t rb[1U<<16];

void limpa(){
   
    printf("Matando filho: %d e pai: %d\n", ringbuff->pids[1], ringbuff->pids[0]);
    //kill(SIGKILL, ringbuff->pids[1]);
    //kill(SIGKILL, ringbuff->pids[0]);
    system("killall gateway");

    shm_unlink(MEMPOOL_REGION);
    shm_unlink(RINGBUF_REGION);



    exit(0);
}


/*****************************************************/
void func_filho(){

    int pidf = getpid();
    ringbuff->pids[1] = pidf;
    
    char settar_cpu[100];
    sprintf(settar_cpu, "taskset -cp 5 %d", pidf);
    system(settar_cpu);

    siginfo_t data_rcv; 
    sigval_t data_send; 
    sigset_t set;
    int sigrtmin1 = SIGRTMIN+1;
    
    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGRTMIN+1);            
    sigprocmask(SIG_BLOCK, &set, NULL); 



    printf("\nPid do filho: %d\n", pidf);

    uint64_t cont_sinal = 0;
    struct teste *temp = NULL;
    uint64_t addr=-1;

    while( sigwaitinfo(&set, &data_rcv) > 0 ){

        //printf("==PROC FIL== recebeu sinal...(%ld)\n", cont_sinal);
        //fflush(stdout);

        addr = sigshared_mempool_get(mempool);
        //while(addr < 0){
        //   
        //    printf("#################\n");
        //    addr = sigshared_mempool_get(mempool);
            if( addr < 0){
                printf("==PROC FILHO== ERRO em mempool_get()\n");
        //        //printf("Terminando processo filho...\n");
        //        //limpa();
            }
        //}

        //temp = sigshared_mempool_access(addr);
        //sigshared_print("==PROC FIL== addr: %ld| head:%ld | tail:%ld | temp: %d\n", addr, ringbuff->head, ringbuff->tail, temp->nf_id);

        //temp->nf_id = pidf;
        //sprintf(temp->vetor_teste, "addr: %ld", addr);
        //sprintf(temp->vetor_teste, "cont: %ld", cont_sinal++);
        sigshared_print("==PROC FIL== addr: %ld| head:%ld | tail:%ld | temp: %d\n", addr, ringbuff->head, ringbuff->tail, /*temp->nf_id*/ ringbuff->rb[ringbuff->ringbuffer[ ringbuff->head-1] ]);

        //printf("==PROC FIL== DEPOIS DO GET --> head: %ld | 1498560tail: %ld\n", ringbuff->head, ringbuff->tail);
        //sigshared_print("==PROC FIL== DEPOIS DO GET --> head: %ld | tail: %ld", ringbuff->head, ringbuff->tail);

        data_send.sival_ptr = (void *) addr;
        if(sigqueue(ringbuff->pids[2], sigrtmin1, data_send) < 0){
            printf("==PROC FILHO== ERRO AO ENVIAR SINAL \n");
            limpa();
        }

    }
}

/*****************************************************/
int main(int argc, char **argv){
    
    signal(SIGINT ,limpa);
    int gateway_pid = getpid();
    printf("gateway_pid: %d\n", gateway_pid);

    int sigrtmin = SIGRTMIN;
    siginfo_t data_rcv; 
    sigval_t data_send; 
    sigset_t set;
     
    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGRTMIN);            
    sigprocmask(SIG_BLOCK, &set, NULL); 


    mempool = sigshared_create_mem();
    ringbuff = sigshared_mempool_create();


    char settar_cpu[100];
    sprintf(settar_cpu, "taskset -cp 4 %d", gateway_pid);
    system(settar_cpu);

    int pid = fork();

    // Processo filho
    // chama get
    if(pid == 0){
        if( setsid() < 0 )
            exit(-1);      


        printf("Processo filho iniciado...\n");
        func_filho();

        // Espera sinal do load generator
        // quando recber sinal chama get
        // Envia sinal para nf apos get
    }
    // chama put
    else if(pid > 0){
        
        printf("Processo pai iniciado...\n");
        ringbuff->pids[0] = gateway_pid;
        
        uint64_t addr = -1;
        mempool = sigshared_ptr_mem();
        struct teste *aux = (struct teste *) mempool;
        
        // Espera sinal da nf para chamar put
        while( sigwaitinfo(&set, &data_rcv) > 0 ){

            addr = (uint64_t) data_rcv.si_value.sival_ptr;
            //aux = sigshared_mempool_access(addr);
            //sigshared_mempool_access(aux, addr);
            
            //printf("==PROC PAI== DEPOIS DO PUT --> head: %ld | tail: %ld | ringbuffer[tail]: %ld | msg: %s\n", ringbuff->head, ringbuff->tail, ringbuff->rb[ringbuff->ringbuffer[ringbuff->tail]], aux->vetor_teste );
            
            //struct teste *temp = sigshared_mempool_access(addr);
            //printf("==PROC PAI== colocando nf_id:%d addr: %s", temp->nf_id, temp->vetor_teste);
            

            int ret_put = sigshared_mempool_put(addr);
            if(ret_put < 0){
                printf("==PROC PAI== ERRO no retorno do sigshared_mempool_put()\n");
                limpa();
            }

            sigshared_print("==PROC PAI== DEPOIS DO PUT --> head: %ld | tail: %ld | cont:%s", ringbuff->head, ringbuff->tail, aux[addr].vetor_teste);
        }
    }
    else{
        printf("+++ERRO NO FORK+++\n");
        limpa();
    }

    
    return 0;
}
