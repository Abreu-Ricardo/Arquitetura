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

#define KBUILD_MODNAME "xdp_http"


//#include <linux/bpf.h>
//#include <bpf/bpf_helpers.h>
//#include <linux/if_ether.h>
//#include <linux/ip.h>
//#include <linux/tcp.h>
//#include <linux/if_ether.h>
//#include <iproute2/bpf_elf.h>
//#include <bpf/bpf_endian.h>
//#include <linux/pkt_cls.h>
//#include <netinet/in.h>





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
        __uint(max_entries, 15);
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
//    bpf_printk("Pkt n foi redirecionado! \n");
//    return XDP_PASS;
//}

/*****************************************************************************/

// Esse programa intercept o sinal e dps reenvia o sinal para o PID
//SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
//int handle_sigqueue(struct trace_event_raw_sys_enter *ctx){
//    
//    int id = ctx->id;
//    pid_t pid_alvo = ctx->args[0];
//    int sig      = ctx->args[1];
//    //void *uinfo  = (void *)ctx->args[2];
//    long unsigned int uinfo2  = ctx->args[2];
//    //long unsigned int uinfo3  = ctx->args[3];
//    //long unsigned int uinfo4  = ctx->args[4];
//    //long unsigned int uinfo5  = ctx->args[5];
//
//    bpf_printk("rt_sigqueueinfo: pid=%d sig=%d id=%d uinfo=%ld\n",
//               pid_alvo, sig, id , uinfo2 /*, uinfo3, uinfo4, uinfo5*/ );
//
//    return 0;
//}

/*****************************************************************************/

#define MAX_METHOD_LEN 7  /* longest method we care about (e.g. "DELETE"=6) */

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only IPv4 */
    //if (eth->h_proto != bpf_htons(ETH_P_IP))
    if (eth->h_proto != bpf_htons(0x0800))
        return XDP_PASS;

    /* IP header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* ip header length (bytes) and check */
    unsigned int ihl = iph->ihl * 4;
    if (ihl < sizeof(*iph))
        return XDP_PASS;
    if ((void *)iph + ihl > data_end)
        return XDP_PASS;

    /* TCP header */
    struct tcphdr *tcph = (void *)iph + ihl;
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return XDP_PASS;

    /* tcp header length and check */
    unsigned int tcph_len = tcph->doff * 4;
    if (tcph_len < sizeof(*tcph))
        return XDP_PASS;
    if ((void *)tcph + tcph_len > data_end)
        return XDP_PASS;

    /* Optional: only inspect common HTTP ports to reduce noise.
       Uncomment or change ports as needed. */
    {
        __u16 dport = bpf_ntohs(tcph->dest);
        __u16 sport = bpf_ntohs(tcph->source);
        /* if not client->server to port 80/8080, skip */
        if (dport != 80 && dport != 8080 && sport != 80 && sport != 8080)
            return XDP_PASS;
    }

    /* Payload pointer and length */
    unsigned char *payload = (unsigned char *)tcph + tcph_len;
    if (payload >= (unsigned char *)data_end)
        return XDP_PASS;

    long payload_len = (long)((unsigned char *)data_end - payload);
    if (payload_len <= 0)
        return XDP_PASS;

    /* Limit how many bytes we will inspect for the method */
    int max_inspect = payload_len < MAX_METHOD_LEN ? (int)payload_len : MAX_METHOD_LEN;

    /* Buffer for method + NUL */
    char method[MAX_METHOD_LEN + 1];
#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_METHOD_LEN + 1; i++)
        method[i] = 0;

    int method_len = 0;

    /* Unrolled loop with per-iteration bound checks to satisfy verifier */
#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_METHOD_LEN; i++) {
        /* Ensure we won't read past data_end for payload[i] */
        if ((void *)(payload + i + 1) > data_end)
            break;

        if (i >= max_inspect)
            break;

        char c = payload[i];
        /* HTTP method ends at first space or CR/LF (in malformed cases too) */
        if (c == ' ' || c == '\r' || c == '\n')
            break;

        /* store character */
        method[i] = c;
        method_len++;
    }

    //if (method_len > 0) {
        /* print method — heavy for production, use perf ring for real use */
        bpf_printk("HTTP method: %s\n", method);
    //}

    return XDP_PASS;
}

//char LICENSE[] SEC("license") = "GPL";




char _license[] SEC("license") = "GPL";
