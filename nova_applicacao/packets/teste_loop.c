#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/*************************************************************************/
static __always_inline volatile long long RDTSC() {

    //register long long TSC asm("eax");
    //asm volatile (".byte 15, 49" : : : "eax", "edx");
    //return TSC;

    unsigned int lo, hi;

    asm ("rdtsc" : "=a" (lo), "=d" (hi)); // Execute RDTSC and store results
    return ((long long)hi << 32) | lo;            // Combine high and low parts
}
/*************************************************************************/



int main(int argc, char **argv){

    if (argc < 2){
        printf("%s num_ciclos\n",argv[0]);
        return 1;
    }
    int pid = getpid();
    char temp[50];

    sprintf(temp,"sudo taskset -cp 4 %d", pid);
    system(temp);

    long long int cont = atoi(argv[1]);
    long long int i=0, start, end;
    start = end = 0;


    // Em media demora 2.3-2.5 ciclos por laco e 2448-2500 ciclos para 1000 iteracoes
    // 1000 iteracoes demora 0.680us
    start = RDTSC();
    while(i < cont){
        i++;
    }
    end = RDTSC();

    printf("\n%lld(end) - %lld(start) = %lld ciclos\n", end, start, (end - start));
    printf("Valor final em us: %.3lf us\n", ((double)(end - start)) / 3600);
    return 0;
}
