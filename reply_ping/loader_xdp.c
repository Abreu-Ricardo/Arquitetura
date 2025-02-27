#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>


#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <linux/bpf.h>

#include "xdp_test.skel.h"

int main(){

    struct xdp_test_bpf *skel;

    skel = xdp_test_bpf__open_and_load();
    if (!skel){
        perror("Erro ao abrir/carregar programa");
        goto erro;
    }

    // *** IMPORTANTE ***
    // A funcao attach do skel.h n funciona com programas XDP e provavelmente com TC
    // por isso eh preciso usar as funcoes especificas
    skel->links.descarta_pkt =  bpf_program__attach_xdp( skel->progs.descarta_pkt , 2 );
    if ( !skel->links.descarta_pkt ){
        perror("Erro ao aclopar o programa");
        goto erro;
    }

    printf("\nEntrando no loop...\n");

    while(1){ ; }

    return 0;

erro:
    printf("Houve erro no carregamento do programa eBPF\n");
    xdp_test_bpf__destroy(skel);
    return 1;
}
