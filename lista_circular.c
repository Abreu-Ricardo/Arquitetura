//#include <stdio.h>
//#include <string.h>
//#include <stdlib.h>
//
//
//struct item{
//    int dado;
//    struct item *prox;
//};
//
//struct ptr{
//    struct item *last;
//};
//
//
////void insere_lista(struct item *p, int valor){
//void insere_lista(struct ptr *p, int valor){
//    
//    struct item *aux = (struct item *) malloc( sizeof(struct item) );
//
//    if (aux != NULL){
//        aux->dado = valor;
//
//        // Primeiro caso: Primeiro elemento a ser inserido
//        if (p->last == NULL){
//            p->last = aux;
//
//            //aux->prox = p;
//            aux->prox = aux;
//        }
//        // Segundo caso: Demais elementos a serem inseridos
//        else{
//            
//            struct item *aux_temp;
//            aux_temp = p->last->prox; 
//
//            while( aux_temp->prox != p->last ){    
//                //printf("LOOP %d\n", aux_temp->dado);
//                aux_temp = aux_temp->prox;
//            }
//
//    
//            aux_temp->prox = aux;
//            aux->prox = p->last;
//        }
//    }
//}
//
///*******************************************************************/
//
////void imprime(struct item *p){
//void imprime(struct ptr *p){
//
//    struct item *aux;
//        
//    aux = p->last;
//    while( aux->prox != p->last){
//        printf("valor: %d\n", aux->dado);
//        aux = aux->prox; 
//    }
//
//    // Ultimo valor antes de chegar no ponteiro de novo
//    printf("valor: %d\n", aux->dado);
//
//    return;
//}
//
///*********************************************************************/
//
//int main(int argc, char **argv){
//    
//    struct ptr *p = (struct ptr *) malloc(sizeof(struct ptr));
//    p->last = NULL;
//    //p->dado = -1;
//    //p->prox = NULL;
//
//    for(int i=0; i<10; i++){
//        insere_lista(p, i);
//    }
//
//    imprime(p);
//
//    return 0;
//}

/*******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>




struct item{
    int dado;
    struct item *prox;
};

struct ptr{
    struct item *last;
};


//void insere_lista(struct item *p, int valor){
void insere_lista(struct item *p, int valor){
    

    struct item *aux = (struct item *) malloc( sizeof(struct item) );

    if (aux != NULL){
        aux->dado = valor;

        // Primeiro caso: Primeiro elemento a ser inserido
        if ( p->dado == -1 ){
            p->dado = valor;
            p->prox = p;

        }
        // Segundo caso: Demais elementos a serem inseridos
        else{
            
            struct item *aux_temp;
            aux_temp = p->prox; 

            while( aux_temp->prox != p ){ 
                printf("LOOP %d\n", aux_temp->dado);
                aux_temp = aux_temp->prox;
            }

    
            aux_temp->prox = aux;
            aux->prox = p;
        }
    }


    return;
}

/*******************************************************************/

//void imprime(struct item *p){
void imprime(struct item *p){

    struct item *aux;
        
    aux = p;
    while( aux->prox != p){
        printf("valor: %d\n", aux->dado);
        aux = aux->prox; 
    }

    // Ultimo valor antes de chegar no ponteiro de novo
    printf("valor: %d\n", aux->dado);

    return;
}

/*********************************************************************/

int main(int argc, char **argv){
    
    //struct ptr *p = (struct ptr *) malloc(sizeof(struct ptr));
    struct item *p = (struct item *) malloc(sizeof(struct item));
    //p->dado = -1;
    //p = NULL;
    p->dado = -1;
    p->prox = NULL;

    for(int i=0; i<10; i++){
        printf("\np na func main %p\n", p);
        insere_lista( p, i);
    }

    imprime(p);

    return 0;
}

