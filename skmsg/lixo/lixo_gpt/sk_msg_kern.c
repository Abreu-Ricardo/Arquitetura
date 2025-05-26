// sk_msg_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 64);
    __type(key, __u32);     // Key to find sockets
    __type(value, __u64);   // Socket FD
} sock_hash_map SEC(".maps");

SEC("sk_msg")
int bpf_sock_msg_redirect(struct sk_msg_md *msg) {
    __u32 key = 1;  // Example key to lookup

    bpf_printk("entrou!!\n");
    // Redirect message to socket with key == 1
    return bpf_msg_redirect_hash(msg, &sock_hash_map, &key, BPF_F_INGRESS);
}

char LICENSE[] SEC("license") = "GPL";
