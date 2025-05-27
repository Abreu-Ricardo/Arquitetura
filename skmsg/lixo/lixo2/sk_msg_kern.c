// sk_msg_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    //__uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);     // Key to find sockets
    __type(value, __u64);   // Socket FD
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_map SEC(".maps");


struct {
    //__uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);     // Key to find sockets
    __type(value, __u64);   // Socket FD
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} test_map SEC(".maps");

SEC("sk_msg")
int bpf_sock_msg_redirect(struct sk_msg_md *msg) {
    __u32 key = 0;  // Example key to lookup
    __u64 *ptr;

    bpf_printk("entrou sk_msg!!\n");
    
    ptr = bpf_map_lookup_elem(&test_map, &key);
    if (!ptr)
        bpf_printk("erro ao acessar o mapa test_map\n");


    // Redirect message to socket with key == 1
    //return SK_DROP;
    //return bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS);
    return bpf_msg_redirect_map(msg, &sock_map, key, BPF_F_INGRESS);
}

char LICENSE[] SEC("license") = "GPL";
