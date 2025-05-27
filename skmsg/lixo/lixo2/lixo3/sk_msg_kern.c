#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} sockhash_map SEC(".maps");

SEC("sk_msg")
int redirect_sk_msg(struct sk_msg_md *msg)
{
    __u32 key = 1; // The key we want to redirect to
    int ret = bpf_msg_redirect_hash(msg, &sockhash_map, &key, BPF_F_INGRESS);
    if (ret != SK_PASS) {
        bpf_printk("Redirect failed: %d\n", ret);
    } else {
        bpf_printk("Redirected packet to key %d\n", key);
    }
    return ret;
}

char LICENSE[] SEC("license") = "GPL";
