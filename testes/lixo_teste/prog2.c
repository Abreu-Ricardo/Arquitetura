#include <stdio.h>
#include <unistd.h>
#include <pthread.h>


int faznda(){

    printf("Faz nada aqui\n");

    int j =1;
    for(int i =0 ; i<100000; i++)
        j= (1 + 1) / 1;

    return j;

}


/*********************************************************************************/
void espera_y_processa(){
    printf("espera y processa...\n");

    int i=1;
    
    while(1){

        sleep(1);
        //printf("<espera y processa> %d\n", getpid());
        printf("Print random\n");
        
        i = i * 1;
    }

    return;
}

/*********************************************************************************/
void soh_processa(){
    
    printf("soh_processa...\n");

    int i = 1;
    while(1){
        i *= 1;
        int faznda();
        //printf("<soh_processa>%d\n", getpid());
        //printf("Dentro do while soh_processa...\n");
        printf("");
    }


    return;
}

/*********************************************************************************/
void nao_processa(){
    printf("nao_processa...\n");

    while(1){
        //printf("<nao_processa> %d\n", getpid());
        int faznda();
        ;
    }

    return;
}


/*********************************************************************************/
int main(){

    printf("PID -->%d\n", getpid());

    pthread_t threads[3];

    pthread_create( &threads[0], NULL, (void *)espera_y_processa, NULL);
    pthread_create( &threads[1], NULL, (void *)soh_processa, NULL);
    pthread_create( &threads[2], NULL, (void *)nao_processa, NULL);
 
    pthread_join(threads[0], NULL);
    pthread_join(threads[1], NULL);
    pthread_join(threads[2], NULL);

    printf("FIM PROGRAMA\n"); 


    while(1){;}

    return 0;
}
