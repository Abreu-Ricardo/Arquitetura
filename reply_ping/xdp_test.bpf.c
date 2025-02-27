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

long long int cont = 0;

SEC("xdp")
int descarta_pkt( struct xdp_md *ctx){

    cont +=1;
    bpf_printk("Descartando pkt...%d", cont);
    return XDP_DROP;
}


char _license[] SEC("license") = "GPL";

