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

    int ret_attach = xdp_test_bpf__attach(skel);
    if (ret_attach < 0){
        perror("Erro ao aclopar o programa");
        goto erro;
    }

    while(1){ ; }


    return 0;

erro:
    xdp_test_bpf__destroy(skel);
    return 1;
}
