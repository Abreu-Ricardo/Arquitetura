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


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, int);
    __type(value, int);
   // __uint(pinning, LIBBPF_PIN_BY_NAME);
} temp SEC(".maps");


// TODO
// Fazer o cliente salvar o FD do socket dele na posicao 1 do mapa
SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg){
    //bpf_printk("ENTROU NO PROGRAMA");

    int key = 1, chave=0, retorno;
    __u64 *ptr;

    ptr = bpf_map_lookup_elem(&temp , &chave); 

    // 10.10.10.1 --> 168430081
    // 10.10.10.2 --> 168430082
    if (bpf_ntohl(msg->remote_ip4) == 168430082){
        
        retorno = bpf_msg_redirect_map(msg, &sock_ops_map, key, BPF_F_INGRESS);
        bpf_printk("Deu trigger| ip remoto:%u | ip local:%u\n", bpf_ntohl(msg->remote_ip4),
                                                                bpf_ntohl(msg->local_ip4));
        
        if (retorno != SK_PASS)
            bpf_printk("Erro no bpf_msg_redirect_map\n");
        
        return retorno;
        //return SK_PASS;
    }
    
    return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
