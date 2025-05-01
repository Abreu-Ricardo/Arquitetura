// signal_monitor.bpf.c

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
//#include <bpf/bpf.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/pkt_cls.h>
#include <linux/netlink.h>

//#include "vmlinux.h"

//struct {
//	__uint(type, BPF_MAP_TYPE_ARRAY);
//	__uint(max_entries, 1);
//	__type(key, __u32);
//	__type(value, sizeof(pid_t));
//} valores SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, sizeof(pid_t));
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} valores SEC(".maps");



SEC("xdp")
//int pega_pkt(struct __sk_buff *ctx) {
int pega_pkt(struct xdp_md *ctx) {

    __u32 key = 0;
    __u64 *ptr;
    
    ptr =  bpf_map_lookup_elem( &valores, &key);
    if(ptr == NULL ){
        bpf_printk("Erro no lookup do mapa\n");
    	return XDP_PASS;
    	//return TCX_DROP;
    }
    //
    //
    int pid = *ptr;
    __u32 temp = bpf_minha_func(pid, 10);

    if (temp < 0){
	bpf_printk("Erro ao enviar o sinal\n");
    	return XDP_PASS;
    	//return TCX_DROP;
    }

    bpf_printk("ESTA CAPTANDO PKTS!!! valor do pid, mapa--> %d\n",  *ptr);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL"; 


//char LICENSE[] SEC("license") = "Dual BSD/GPL"; 
//
//modprobe cls_bpf
//lsmod | grep cls_bpf
//grep -i bpf /boot/config-$(uname -r)
//sudo bpftool feature probe | grep -i  program_type
