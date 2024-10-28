// xdp_program.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>   // inclui as funcs do TC
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>	    // struct iphr
#include <linux/udp.h>
#include <bpf/bpf_endian.h> // bpf_ntohs()
#include <linux/icmp.h>

// MAP
struct{ 
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);    
} pkt_counter SEC(".maps");


/***********************************************************************************************/
static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx){
	unsigned char protocol = 0;

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return 0;

	// Verificar se eh um pacote IP
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){
		// Protocolo do pacote
		// 1 = ICMP
		// 6 = TCP
		// 17 = UDP

		struct iphdr *iph = data + sizeof(struct ethhdr);
		
        if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
			protocol = iph->protocol;
			bpf_printk("protocolo:%d  \n", protocol);
        }
	}
	return protocol;
}

/*****************************************************************************/

/***********************************************************************************************/
// CODE XDP
SEC("xdp")
int recebe_pacotes(struct xdp_md *ctx ){
	__u32 key = 0;
	__u64 protocolo = lookup_protocol(ctx);
	__u64 *count;

    __u32 redir = 0;




	// TODO
	// Redirecionar o pacote para o host para que os programas continuem a funcionar, ping e iperf3
    
	
	// Filtra pacotes 
        if (protocolo == 1){ // Filtra pacotes
            count = bpf_map_lookup_elem(&pkt_counter, &key);
            bpf_printk("EH ICMP\n");

            if (count != NULL){
                (*count)++;
                //bpf_printk("recebe_kern: %d ret:%d\n", *count, ip_ret);
            }
            return XDP_DROP;

                        // (INDEX DA INTERFACE , CODIGO BPF_F_INGRESS ou 0)
	}
   
    bpf_printk("protocolo:%d  \n", protocolo);

	return XDP_PASS;

}

char _license[] SEC("license") = "GPL";
