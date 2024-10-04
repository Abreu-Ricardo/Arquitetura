#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>   // inclui as funcs do TC
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>	    // struct iphr
#include <bpf/bpf_endian.h> // bpf_ntohs()

// MAP
//struct mapa_mem{ 
//	__uint(type, BPF_MAP_TYPE_ARRAY);
//	__uint(max_entries, 1);
//	__type(key, __u32);
//	__type(value, __u64); // Ver o tipo da var que o fd de mem eh   
//    __uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
//} mapa_fd SEC(".maps");



struct mapa_mem{ 
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, sizeof(char) * 50); // Ver o tipo da var que o fd de mem eh   
//    __uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
} mapa_fd SEC(".maps");



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

// CODE XDP
SEC("xdp")
int teste(struct xdp_md *ctx ){
    __u32 key=0;
    __u64 *ptr;

    ptr = bpf_map_lookup_elem(&mapa_fd, &key);

    if (ptr != NULL){
        //*(ptr) = *(ptr) + 1;
        bpf_printk("Valor do fd no mapa: %d\n", *ptr);
    }

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

