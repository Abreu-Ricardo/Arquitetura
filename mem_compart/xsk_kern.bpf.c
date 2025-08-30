#include "vmlinux.h"

//#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // bpf_ntohs()

//#include <linux/pkt_cls.h>   // inclui as funcs do TC
//#include <iproute2/bpf_elf.h>
//#include <linux/if_ether.h> // struct ethhdr
//#include <linux/ip.h>	    // struct iphr
//#include <linux/udp.h>
//#include <linux/icmp.h>
//#include <stdint.h>
//#include <time.h>


//#include <netinet/tcp.h>
// Salvar o nome da regiao de mem, ja que o
// open_shm() usa nome de regiao de mem para identificar
struct mapa_mem{ 
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, sizeof(char) * 50); // Ver o tipo da var que o fd de mem eh   
 //   __uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
} mapa_fd SEC(".maps");


// Mapa usado para que o usar space acesse e coloque o PID do processo
// a ser sinalizado
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 10);
        __type(key, __u32);
        __type(value, sizeof(pid_t)); 
    	//__uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
} mapa_sinal SEC(".maps");

// Mapa necessario para salvar tempos do rdtsc() do sinal
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1000);
        __type(key, __u32);
        __type(value, __u64); // Ver o tipo da var que o fd de mem eh   
    	//__uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
} tempo_sig SEC(".maps");

// Define um mapa XSKMAP para o socket AF_XDP
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 4); 
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");



/*****************************************************************************/
__u32 pkt_global = 0;

//SEC("xdp")
//int xdp_prog(struct xdp_md *ctx){
//    bpf_printk("Capturou o pkt!\n");
//    // Redireciona o pacote para o socket XDP associado no mapa xsk_map
//    //int index = ctx->rx_queue_index; //0; // index do socket
//    int ret, key = 0; // indice 0 eh para o primeiro socket e 1 para o segundo socket
//    
//    __u64 *ptr;
//    __u64 *ptr_sig;
//    __u32 ret_final;
//    __u64 ret_func;
//
//    ptr = bpf_map_lookup_elem(&mapa_sinal, &key);
//
//
//
//    //bpf_printk("Pkt n foi redirecionado! %d\n", ret);
//    return XDP_PASS;
//}

/*****************************************************************************/

// Esse programa intercept o sinal e dps reenvia o sinal para o PID
SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
int handle_sigqueue(struct trace_event_raw_sys_enter *ctx){
    
    int id = ctx->id;
    pid_t pid_alvo = ctx->args[0];
    int sig      = ctx->args[1];
    //void *uinfo  = (void *)ctx->args[2];
    long unsigned int uinfo2  = ctx->args[2];
    //long unsigned int uinfo3  = ctx->args[3];
    //long unsigned int uinfo4  = ctx->args[4];
    //long unsigned int uinfo5  = ctx->args[5];

    bpf_printk("rt_sigqueueinfo: pid=%d sig=%d id=%d uinfo=%ld\n",
               pid_alvo, sig, id , uinfo2 /*, uinfo3, uinfo4, uinfo5*/ );

    return 0;
}

char _license[] SEC("license") = "GPL";
