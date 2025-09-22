#include "shm_test.h"
#include <time.h>  

struct sigshared_ringbuffer *ringbuff;
void *mempool = NULL;


struct teste *temp_test = NULL;

void limpa(){

    shm_unlink(MEMPOOL_REGION);
    shm_unlink(RINGBUF_REGION);

    exit(0);
}

/**********************************************************/
int main(int argc, char **argv){
    
    signal(SIGINT ,limpa);
    
    int nf_pid = getpid();
    printf("nf_pid: %d\n", nf_pid);

    mempool = sigshared_ptr_mem();
    ringbuff = sigshared_mempool_ptr();

    printf("ringbuff->head: %ld\nringbuff->tail: %ld\n", ringbuff->head, ringbuff->tail);
    fflush(stdout);
    ringbuff->pids[2] = nf_pid;

    printf("%d %d %d\n", ringbuff->pids[0], ringbuff->pids[1], ringbuff->pids[2]);
    
    fflush(stdout);
    int sigrtmin = SIGRTMIN;
      
    siginfo_t data_rcv; 
    sigval_t data_send; 
    sigset_t set;
     
    sigemptyset(&set);                   // limpa os sinais que pode "ouvir"
    sigaddset(&set, SIGRTMIN+1);            
    sigprocmask(SIG_BLOCK, &set, NULL); 

    uint64_t addr = 0;
    uint64_t cont_sig = 0;
    srand(time(NULL));

    temp_test = (struct teste *) mempool;
    printf("temp_test:%p | mempool: %p\n", temp_test, mempool);

    while( sigwaitinfo(&set, &data_rcv) > 0 ){
        //printf("==NF== recebeu sinal...\n");
        //fflush(stdout);

        //sigshared_print("==NF== recebeu sinal... %d",  cont_sig++);
   

        //usleep( rand() % 5000 );
        //sleep( 0.01 );
        
        for(int i =0; i < 5000000; i++){
            ;
        }


        addr = (uint64_t)data_rcv.si_value.sival_ptr;
        //temp_test = sigshared_mempool_access(addr);
        //sigshared_mempool_access(temp_test, addr);
        if( &temp_test[addr] == NULL){
            printf("==NF-ERROR== ERRO ao accessar regiao de mem | addr: %ld\n", addr);
            exit(1);
        }

        
        temp_test[addr].nf_id = (int)cont_sig;
        sprintf( temp_test[addr].vetor_teste ,"Conteudo escrito num: %ld", cont_sig++);

        sigshared_print("==NF==%s | cont:%d", temp_test->vetor_teste, cont_sig);

        data_send.sival_ptr = (void *) addr;
        if(sigqueue(ringbuff->pids[0], sigrtmin, data_send) < 0){
            printf("==NF== ERRO AO ENVIAR SINAL \n");
            exit(1);
        }
        
    }
    
    return 0;
}
