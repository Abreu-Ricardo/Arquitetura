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

//struct mapa_mem{ 
//	__uint(type, BPF_MAP_TYPE_ARRAY);
//	__uint(max_entries, 1);
//	__type(key, __u32);
//	__type(value, sizeof(char) * 50); // Ver o tipo da var que o fd de mem eh   
////    __uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
//} mapa_fd SEC(".maps");



// Define um mapa XSKMAP para o socket AF_XDP
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 4); // Suporta uma única entrada de socket para simplificação
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");


/****************************************************************************/
static __always_inline int verifica_ip(struct xdp_md *ctx){

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
    unsigned char protocol = 0;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
        return -1; 
	}

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){	
		struct iphdr *iph = data + sizeof(struct ethhdr);

        // Verificar se eh um pacote IP
        if (bpf_ntohs(eth->h_proto) == ETH_P_IP){
            // Protocolo do pacote
            // 1 = ICMP
            // 6 = TCP
            // 17 = UDP

            struct iphdr *iph = data + sizeof(struct ethhdr);
            if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
                protocol = iph->protocol;

                //struct icmphdr *icmp = data + sizeof(struct iphdr); 
                //if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) <= data_end ){
                //    protocol = 1;
                //}

            }
	    }
    }
	return protocol; 
}
/*****************************************************************************/


SEC("xdp")
int xdp_prog(struct xdp_md *ctx){
    // Redireciona o pacote para o socket XDP associado no mapa xsk_map
    int index = 0; //ctx->rx_queue_index; //0; // index do socket
    int ret;
    
    //__u32 *ptr = bpf_map_lookup_elem(&mapa_fd, 0);
    ret = verifica_ip(ctx);
    
    return bpf_redirect_map(&xsk_map, index, BPF_F_INGRESS);

    //if(ret == 1){
    //    bpf_printk("Pacote ICMP redirecionado! code:%d\n", ret);
    //    //return XDP_DROP;
    //    return bpf_redirect_map(&xsk_map, index, BPF_F_INGRESS);
    //}
    //else{
    //    bpf_printk("Outros pkts passando... code:%d\n", ret);
    //    return bpf_redirect_map(&xsk_map, index, 0);
    //    //return XDP_PASS;
    //}
}

char _license[] SEC("license") = "GPL";
