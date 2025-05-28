#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>

// Trocar isso
#define LOCALHOST_IPV4 16777343 // 127.0.0.1 in network byte order


struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 4);
    __type(key, int);
    __type(value, int);
   // __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_ops_map SEC(".maps");


// TODO
// Fazer o cliente salvar o FD do socket dele na posicao 1 do mapa
SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
    bpf_printk("DEU TRIGGER NO PROGRAMA\n");


    // 10.10.10.1 --> 168430081
    // 10.10.10.2 --> 168430082
    if (bpf_htonl(msg->remote_ip4) == 168430082){
        bpf_printk("Pacote sendo enviado do servidor para o cliente");
        return SK_PASS;
    }
    
    int chave = 0; 
    int ret = bpf_msg_redirect_map(msg, &sock_ops_map, chave, BPF_F_INGRESS);
    //bpf_printk("Retorno de msg_redirect_map: %d | IP %u\n", ret, msg->local_port);
    bpf_printk("Retorno de msg_redirect_map: %d | IP %u\n", ret, bpf_ntohl(msg->remote_ip4));
    return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
