#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 10);
    __type(key, __u32); 
    __type(value, __u64); 
    //__uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_map SEC(".maps");

SEC("sk_msg")
int bpf_sock_msg_redirect(struct sk_msg_md *msg)
{
    __u32 key = 0; 
        
    bpf_printk("Entrou no programa eBPF\n");

    int ret = bpf_msg_redirect_map(msg, &sock_map, key, BPF_F_INGRESS);
    return ret;
}

char LICENSE[] SEC("license") = "GPL";
