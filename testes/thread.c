
#include<stdio.h>
#include<stdlib.h>
#include<pthread.h>

typedef struct{

    int dia;
    int mes;
    int ano;
}data;

void inicio(data *d_teste){
    printf("DATA: %d/%d/%d\nIniciando teste...\n", d_teste->dia, d_teste->mes, d_teste->ano);
    while(1){
    }
}



int main(int argc, char **argv){

    pthread_t thr;
    data d_teste;

    d_teste.dia = 14;
    d_teste.mes = 12;
    d_teste.ano = 2024;

    pthread_create(&thr ,NULL , (void *)inicio, &d_teste);
    pthread_join(thr, NULL);

    return 0;
}
