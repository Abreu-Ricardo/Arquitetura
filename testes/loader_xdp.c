#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>


/* In this example we use libbpf-devel and libxdp-devel */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

/* We define the following global variables */
static int ifindex;
struct xdp_program *prog = NULL;
struct bpf_object *bpf_obj;


/* This function will remove XDP from the link when the program exits. */
static void int_exit(int sig)
{
	xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
	xdp_program__close(prog);
	exit(0);
}


int main(int argc, char *argv[])
{
	int prog_fd, ret_attach;
	char caminho_prog[200] = "gepeto_kern.o";
  
    
	if (argc != 2) {
		printf("Erro, passe o parametro <interface> ");
		return 1;
	}

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		printf("Erro ao converter o nome da interface para indice\n");
		return 1;
	}
	
	// load XDP object by libxdp 
	prog = xdp_program__open_file(caminho_prog, "xdp", NULL);
	if (!prog) {
		printf("Erro ao abrir o programa xdp\n");
		return 1;
	}

	// attach XDP program to interface with xdp mode
	// Please set ulimit if you got an -EPERM error.
	//

	ret_attach = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
	if (ret_attach) {
		printf("Error, Set xdp fd on %d failed\n", ifindex);
		return ret_attach;
	}

	// Find the map fd from the bpf object 
	bpf_obj = xdp_program__bpf_obj(prog);
	
    //bpf_obj = bpf_object__open_file(caminho_prog, NULL);
    if (bpf_obj == NULL){
        perror("Erro ao abrir o arquivo para bpf_object");
    }
	
    //int mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "mapa_fd");
	int mapa_fd = bpf_object__find_map_fd_by_name(bpf_obj, "xsk_map"); 
	if (mapa_fd < 0) {
		printf("Erro ao tentar obter o fd do mapa pelo bpf_obj, retorno: %d\n", mapa_fd);
        bpf_object__close(bpf_obj);
		return mapa_fd;
	}
	
    /* Remove attached program when it is interrupted or killed */
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);


    while(1)
        ;





	return 0;
}
