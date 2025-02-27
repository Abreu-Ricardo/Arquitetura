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
// __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
// __uint(max_entries, 1);
// __uint(key, __u32);
// __uint(value, sizeof(__u32));
//} valores SEC(".maps");



SEC("tc")
int pega_pkt(struct __sk_buff *ctx) {

    __u32 *key = 0;

    //bpf_map_lookup_elem( &valores, key);

    bpf_printk("ESTA CAPTANDO PKTS!!!\n");

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL"; 


//char LICENSE[] SEC("license") = "Dual BSD/GPL"; 
//
//modprobe cls_bpf
//lsmod | grep cls_bpf
//grep -i bpf /boot/config-$(uname -r)
//sudo bpftool feature probe | grep -i  program_type
