#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>
#include <string.h>

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

/**************************************************************/

void print_ip(uint32_t ip) {
    
    char temp[15];
    // Extract octets using bit shifting and masking
    char  octet1 = (char)(ip >> 24) & 0xFF;
    char  octet2 = (char)(ip >> 16) & 0xFF;
    char  octet3 = (char)(ip >> 8) & 0xFF;
    char  octet4 = (char)(ip & 0xFF);

    strcat(temp ,&octet1);    
    strcat(temp ,&octet2);    
    strcat(temp ,&octet3);    
    strcat(temp ,&octet4);    

    bpf_printk("%u.%u.%u.%u\n", octet1, octet2, octet3, octet4);
    //return &temp;
}
/**************************************************************/

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
        
        //bpf_printk("Deu trigger| ip remoto:%s | ip local:%s\n", bpf_ntohl(msg->remote_ip4),
        //                                                        bpf_ntohl(msg->local_ip4));
        
        bpf_printk("ip local --> ");
        print_ip(bpf_ntohl(msg->local_ip4 ));
        bpf_printk("ip remote--> ");
        print_ip(bpf_ntohl(msg->remote_ip4));
        
        if (retorno != SK_PASS)
            bpf_printk("Erro no bpf_msg_redirect_map\n");
        
        return retorno;
        //return SK_PASS;
    }
    
    return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
