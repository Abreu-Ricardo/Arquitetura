#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define LOCALHOST_IPV4 16777343 // 127.0.0.1 in network byte order

struct sock_key {
    __u32 sip;
    __u32 dip;
    __u32 sport;
    __u32 dport;
    __u32 family;
};

struct {
    //__uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 4);
    //__type(key, struct sock_key);
    __type(key, int);
    __type(value, int);
   // __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_ops_map SEC(".maps");

//SEC("sk_msg")
SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
    bpf_printk("DEU TRIGGER NO PROGRAMA\n");
    // Only handle localhost traffic
    //if(msg->remote_ip4 != LOCALHOST_IPV4 || msg->local_ip4!= LOCALHOST_IPV4) 
    //    return SK_PASS;

    //// Create lookup key based on packet metadata
    //struct sock_key key = {
    //    .sip = msg->remote_ip4,
    //    .dip = msg->local_ip4,
    //    .dport = bpf_htonl(msg->local_port),
    //    .sport = msg->remote_port,
    //    .family = msg->family,
    //};

    int chave = 0;
    // Redirect message to socket found in map
    //return bpf_msg_redirect_hash(msg, &sock_ops_map, &key, BPF_F_INGRESS);
    
    int ret = bpf_msg_redirect_map(msg, &sock_ops_map, chave, BPF_F_INGRESS);
    bpf_printk("Valor retornado de msg_redirect_map: %d\n", ret);
    return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
