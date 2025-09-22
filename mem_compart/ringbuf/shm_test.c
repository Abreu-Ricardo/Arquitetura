#include "shm_test.h"

extern struct sigshared_ringbuffer *ringbuff;
extern void *mempool;
extern struct test *temp_test;


extern uint64_t rb[1U<<16];

int fd_shm = -1;

/*********************************************************************/
void sigshared_print(const char *format, ...) {
    // Move cursor to beginning of line
    printf("\r");
    
    // Clear the line
    printf("\033[2K");
    
    // Print the message
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    // Flush the buffer to ensure immediate display
    fflush(stdout);
}

/*********************************************************************/
void *sigshared_create_mem(){

    fd_shm = shm_open(MEMPOOL_REGION, O_RDWR | O_CREAT, 0777);
    if (fd_shm < 0){
        perror("Erro a settar tamanho do ringbuffer");
        exit(1);
    }

    if( ftruncate(fd_shm, MEMPOOL_TAM) < 0 ){
        perror("Erro a settar tamanho do ringbuffer");
        exit(1);
    }

    return (void *) mmap(0, MEMPOOL_TAM, PROT_WRITE, MAP_SHARED, fd_shm, 0);
}

/*********************************************************************/
void *sigshared_ptr_mem(){

    fd_shm = shm_open(MEMPOOL_REGION, O_RDWR | O_CREAT, 0777);
    if (fd_shm < 0){
        perror("Erro ao abrir regiao do ringbuffer");
        return NULL;
        //exit(1);
    }

        
    return (void *) mmap(0, MEMPOOL_TAM, PROT_WRITE, MAP_SHARED, fd_shm, 0);
}

/*********************************************************************/
struct sigshared_ringbuffer *sigshared_mempool_create(){

    int fd_ringbuff = shm_open(RINGBUF_REGION, O_RDWR | O_CREAT, 0777);
    if (fd_ringbuff < 0){
        perror("Erro ao criar mem compart de ringbuff");
        return NULL;
    }

    int ret_truncate = ftruncate( fd_ringbuff, RINGBUF_TAM);
    if(ret_truncate < 0){
        perror("Erro ao atribuir tamanho do ringbuff");
        return NULL;
    }

    ringbuff = (struct sigshared_ringbuffer *) mmap(0, RINGBUF_TAM, PROT_WRITE, MAP_SHARED, fd_ringbuff, 0);
    for(int i=0; i < N_ELEMENTOS; i++){
        ringbuff->ringbuffer[i] = i;
        ringbuff->rb[i] = i;
    }

    // Ultima posicao pois, na criacao todas 
    // posicoes estao livres
    ringbuff->head = 0;
    ringbuff->tail = N_ELEMENTOS - 1;


    return (struct sigshared_ringbuffer *) mmap(0, RINGBUF_TAM, PROT_WRITE, MAP_SHARED, fd_ringbuff, 0);
}

/*********************************************************************/
struct sigshared_ringbuffer *sigshared_mempool_ptr(){

    int fd_ringbuff = shm_open(RINGBUF_REGION, O_RDWR | O_CREAT, 0777);
    if (fd_ringbuff < 0){
        perror("Erro ao criar mem compart de ringbuff");
        return NULL;
    }

    return (struct sigshared_ringbuffer *) mmap(0, RINGBUF_TAM, PROT_WRITE, MAP_SHARED, fd_ringbuff, 0);
}

/*********************************************************************/
int sigshared_mempool_get(void *ptr){
    
    uint64_t head = ringbuff->head;
    uint64_t tail = ringbuff->tail;

    int temp = -1;
    if (ringbuff->head+1 == N_ELEMENTOS ){
    //if ( head+1 == N_ELEMENTOS ){
        
        ringbuff->head = 0;
        //head = 0;
        printf("<mempool_get()> head+1 == N_ELEMENTOS | head:%ld tail:%ld\n", head, tail);

        if (ringbuff->head != ringbuff->tail){
            printf("<mempool_get()> head != tail\n");
            //temp = ringbuff->ringbuffer[ringbuff->head];
            temp = ringbuff->rb[ ringbuff->ringbuffer[ringbuff->head] ];
            ringbuff->head++;
            return temp;
        }
        else{
            while(ringbuff->head == ringbuff->tail){
                printf("+++ERRO1+++ <sigshared_mempool_get()> HEAD == TAIL | head:%ld tail:%ld\n", ringbuff->head, ringbuff->tail);
                usleep(500);
            }
            
            //temp =  ringbuff->ringbuffer[ringbuff->head];
            temp =  ringbuff->rb[ringbuff->ringbuffer[ringbuff->head]];
            return temp;
        }
    }

    else if (ringbuff->head+1 != ringbuff->tail){
        //temp = ringbuff->ringbuffer[ringbuff->head];
        temp = ringbuff->rb[ringbuff->ringbuffer[ringbuff->head]];
        ringbuff->head++;
        return temp;
    }

    else{
        //printf("++ERROR++ HEAD == TAIL \n");
        printf("++++ERRO2+++ <sigshared_mempool_get()> HEAD == TAIL \n");
        
        while(ringbuff->head == ringbuff->tail){
                printf("<sigshared_mempool_get()> HEAD == TAIL \n");
                //exit(1);
                usleep(500);
        }
            
        //temp =  ringbuff->ringbuffer[ringbuff->head];
        temp =  ringbuff->rb[ringbuff->ringbuffer[ringbuff->head]];
        ringbuff->head++;
        return temp;
    }
}

/*********************************************************************/
int sigshared_mempool_put(uint64_t addr){

    // Put chama mas ja esta na ultima posicao
    if(ringbuff->tail+1 == N_ELEMENTOS){
        ringbuff->tail = 0;

        if ( ringbuff->tail != ringbuff->head ){
            //ringbuff->ringbuffer[ringbuff->tail] = addr;
            ringbuff->ringbuffer[ringbuff->tail] = addr;
            ringbuff->tail++;
            return 0;
        }
        else{
            printf("ERRO1==sigshared_mempool_put== HEAD == TAIL \n");
            //sigshared_mempool_put(addr);
            ringbuff->ringbuffer[ringbuff->tail] = addr;
            ringbuff->head = ringbuff->tail+1; 
            return 0;
        }
    }
    else if( ringbuff->tail+1 != ringbuff->head ){
        ringbuff->ringbuffer[ringbuff->tail] = addr;
        ringbuff->tail++;
        return 0;
    }
    // Se tail alcanca head, buffer esta vazio
    // entao por head na frente de tail para consumir
    // as posicoes da frente
    else if (ringbuff->tail+1 == ringbuff->head){
        //ringbuff->tail = N_ELEMENTOS - 1; 
        ringbuff->head = ringbuff->tail; 
        ringbuff->tail++;
        //if(ringbuff->head == N_ELEMENTOS-1)
        //    ringbuff->head= 0;
        //printf("ERRO2==sigshared_mempool_put== HEAD == TAIL \n");
        //sigshared_mempool_put(addr);
        //return -1;
        return 0;
    }

    return 0;
}

/*********************************************************************/
//struct teste *sigshared_mempool_access(uint64_t addr){
struct teste *sigshared_mempool_access(struct teste *temp, uint64_t addr){

    printf("Entrou sigshared_mempool_access() | addr:%ld\n", addr);

    //mempool = sigshared_ptr_mem();
    //void *aux = sigshared_ptr_mem();
    temp = (struct teste *)sigshared_ptr_mem();
    
    printf("nf_id:%d | texto:%s\n",temp[addr].nf_id, temp[addr].vetor_teste);
    //if (aux == NULL){
    if (temp == NULL){
        printf("sigshared_mempool_access: mempool == NULL\n");
        return NULL;
    }
    
    //mempool += (sizeof(struct teste) * ringbuff->ringbuffer[addr]);
    //aux += (sizeof(struct teste) * ringbuff->ringbuffer[addr]);
    //temp += (sizeof(struct teste) * ringbuff->rb[ ringbuff->ringbuffer[addr] ]);
    temp = &temp[addr];
    //aux = &aux[ rb[addr] ];

    //return (struct teste *) aux;
    return temp;
}
/*********************************************************************/
