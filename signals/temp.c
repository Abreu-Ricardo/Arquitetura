#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

SEC("classifier")
int tc_drop(struct __sk_buff *skb) {
    return TC_ACT_SHOT; // Drop the packet
}

char _license[] SEC("license") = "GPL";
