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

struct pkt_stats {
	long pkts;
	long bytes;
};



/**********************************************************************************************************/
// Essa func remove o programa XDP do NIC, quando existir
static void int_exit(int sig)
{
	xdp_program__detach(prog, ifindex, XDP_MODE_NATIVE, 0);
	xdp_program__close(prog);
	exit(0);
}

/**********************************************************************************************************/
static void poll_stats(int global_map_fd, int local_map_fd, int interval)
{
	int ncpus = libbpf_num_possible_cpus();
	int i, key = 0, time = 0;
	struct pkt_stats per_cpu_values[ncpus], global_values;
	
	if (ncpus < 0) {
		printf("Error get possible cpus\n");
		return;
	}
    
	while (1) {
		long sum_pkts, sum_bytes;

		sleep(interval);
      
		assert(bpf_map_lookup_elem(global_map_fd, &key, &global_values) == 0);
		assert(bpf_map_lookup_elem(local_map_fd, &key, per_cpu_values) == 0);
      
		sum_pkts = sum_bytes = 0;
		for (i = 0; i < ncpus; i++) {
			sum_pkts  += per_cpu_values[i].pkts;
			sum_bytes += per_cpu_values[i].bytes;
		}
      
		printf("%d\nGlobal Map: Packets=%ld Bytes=%ld\n", ++time,
		       global_values.pkts, global_values.bytes);
		printf("Local  Map: Packets=%ld Bytes=%ld\n", sum_pkts, sum_bytes);
		if (sum_pkts != global_values.pkts || sum_bytes != global_values.bytes)
			printf("Values differ\n");
		fflush(stdout);
	}
}

/**********************************************************************************************************/
int main(int argc, char *argv[])
{
	int prog_fd, ret, global_map_fd, local_map_fd;
	char file_name[100], sec_name[100];
    
	if (argc != 4) {
		printf("Usage: %s IFNAME tcp|udp -l|-r\n", argv[0]);
		return 1;
	}

    // Pega o num do indice da interface
	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		printf("get ifindex from interface name failed\n");
		return 1;
	}

    // Verifica os parametros passados
	if (strcmp(argv[3], "-l") == 0)
		sprintf(file_name, "%s_count_lock.o", argv[2]);
	else
		sprintf(file_name, "%s_count.o", argv[2]);
	
    // Carrega o arquivo de acordo com o parametro passado
	sprintf(sec_name, "xdp_%s_count", argv[2]);
	
	/* load XDP object by libxdp */
	printf("filename: %s  %s\n", file_name, sec_name);
	prog = xdp_program__open_file(file_name, sec_name, NULL);
	if (!prog) {
		printf("Error, load xdp prog failed\n");
		return 1;
	}

	/* attach XDP program to interface with xdp mode
	 * Please set ulimit if you got an -EPERM error.
	 */
	ret = xdp_program__attach(prog, ifindex, XDP_MODE_NATIVE, 0);
	if (ret) {
		printf("Error, Set xdp fd on %d failed\n", ifindex);
		return ret;
	}

	/* Find the map fd from the bpf object */
	bpf_obj = xdp_program__bpf_obj(prog);
	global_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "map_global");
	if (global_map_fd < 0) {
		printf("Error, get map fd from bpf obj failed\n");
		return global_map_fd;
	}

	local_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "map_local");
	if (local_map_fd < 0) {
		printf("Error, get map fd from bpf obj failed\n");
		return local_map_fd;
	}

	/* Remove attached program when it is interrupted or killed */
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	poll_stats(global_map_fd, local_map_fd, 2);

	return 0;
}

