#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>   // inclui as funcs do TC
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>	    // struct iphr
#include <linux/udp.h>
#include <bpf/bpf_endian.h> // bpf_ntohs()

// MAPA para guardar o nome da regiao de mem
struct mapa_mem{ 
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, sizeof(char) * 50); // Ver o tipo da var que o fd de mem eh   
//    __uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
} mapa_fd SEC(".maps");


// MAPA para copiar os pacotes do kernel para regiao de mem
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 4);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} xsks_map SEC(".maps");


//struct {
//	__uint(type, BPF_MAP_TYPE_RINGBUF);
//	__uint(max_entries, 150 * 1500 /* 256 KB */);
//} ringbuf SEC(".maps");

/*
struct{ 
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, 1); // Mudar num de entradas dps
	__type(key, __u32);
	__array(values, struct mapa_mem);    
} mapa_hash SEC(".maps") = {
    .values = { &mapa_fd }
};
*/


/****************************************************************************/
static __always_inline int verifica_ip(struct xdp_md *ctx){

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
		return 1; // IP  destino n eh o esperado
	}

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){	
		struct iphdr *iph = data + sizeof(struct ethhdr);
		
        if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
           //bpf_printk("EH PACOTE IP\n");


           struct udphdr *udphdr = data + sizeof(struct udphdr);
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) <= data_end ){
			
                bpf_printk("EH PACOTE UDP\n");
                
                return 0;  
            }
            
		}
	}
	return 1; 
}
/*****************************************************************************/

// CODE XDP
SEC("xdp")
int teste(struct xdp_md *ctx ){
    __u32 key=0;
    __u64 *ptr;
    __u32 tam_data = ctx->data_end - ctx->data;
    
    void *teste;
    teste = &ctx->data;

    
    //verifica_ip(ctx);

    //bpf_printk("TRIGGER no codigo eBPF no kernel\n");
    

    ptr = bpf_map_lookup_elem(&mapa_fd, &key);

    if (ptr != NULL){
        *(ptr) = *(ptr) + 1;
        bpf_printk("Acessando mapa contador de pkt: %d\n", *ptr);
    }

    if (verifica_ip(ctx) == 0){
        return bpf_redirect_map(&xsks_map, 0, 0);
    }

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";


