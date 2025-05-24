#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 128);
    __type(key, __u32); // Can be socket cookie or connection ID
    __type(value, __u64); // Socket FD
    __uint(map_flags, 0);
} sock_hash_map SEC(".maps");

// BPF program of type sk_msg
SEC("sk_msg")
int bpf_sock_msg_redirect(struct sk_msg_md *msg)
{
    //__u32 key = 1; // redirect to the socket with key == 1
    __u32 key = 0; // redirect to the socket with key == 1

    int ret = bpf_msg_redirect_hash(msg, &sock_hash_map, &key, BPF_F_INGRESS);
    return ret;
}

char LICENSE[] SEC("license") = "GPL";
