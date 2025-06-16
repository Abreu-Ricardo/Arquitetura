// xdp_program.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>   // inclui as funcs do TC
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>	    // struct iphr
#include <linux/udp.h>
#include <bpf/bpf_endian.h> // bpf_ntohs()
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

// Salvar o nome da regiao de mem, ja que o
// open_shm() usa nome de regiao de mem para identificar
struct mapa_mem{ 
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, sizeof(char) * 50); // Ver o tipo da var que o fd de mem eh   
 //   __uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
} mapa_fd SEC(".maps");


// Mapa usado para que o usar space acesse e coloque o PID do processo
// a ser sinalizado
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, sizeof(pid_t)); 
    	//__uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
} mapa_sinal SEC(".maps");

// Mapa necessario para salvar tempos do rdtsc() do sinal
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1000);
        __type(key, __u32);
        __type(value, __u64); // Ver o tipo da var que o fd de mem eh   
    	//__uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
} tempo_sig SEC(".maps");

// Define um mapa XSKMAP para o socket AF_XDP
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 4); 
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

/****************************************************************************/
unsigned char protocol = 0;
void *data; 
void *data_end;

struct ethhdr *eth;
struct iphdr *iph;

static __always_inline int verifica_ip(struct xdp_md *ctx){

	//void *data = (void *)(long)ctx->data;
	//void *data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    protocol = 0;

	eth = data;
	if (data + sizeof(struct ethhdr) > data_end){
        	return -1; 
	}

	if (bpf_ntohs(eth->h_proto) == ETH_P_IP){	
		 iph = data + sizeof(struct ethhdr);

        // Verificar se eh um pacote IP
        //if (bpf_ntohs(eth->h_proto) == ETH_P_IP){
            // Protocolo do pacote
            // 1 = ICMP
            // 6 = TCP
            // 17 = UDP

            if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
                protocol = iph->protocol;


            }
	    //}
    }
	return protocol; 
}
/*****************************************************************************/
SEC("xdp")
int xdp_prog(struct xdp_md *ctx){

	//bpf_printk("ENTROU NO PROGRAMA xdp");
    // Redireciona o pacote para o socket XDP associado no mapa xsk_map
    //int index = ctx->rx_queue_index; //0; // index do socket
    int ret, key = 0; // indice 0 eh para o primeiro socket e 1 para o segundo socket
    
    __u64 *ptr;
    __u64 *ptr_sig;
    __u32 ret_final;
    __u64 ret_func;

    //uint64_t pid_tgid = bpf_get_current_pid_tgid();
    //uint32_t pid = pid_tgid & 0xFFFFFFFF;
    //uint32_t tgid = pid_tgid >> 32;

    ret = verifica_ip(ctx);
    ptr = bpf_map_lookup_elem(&mapa_sinal, &key);

    //if( ret == 17){
    if( ptr != NULL  && ret == 1 /*&& ptr_sig != NULL*/){
        //if (ret == 17){

        ret_final = bpf_redirect_map(&xsk_map, key, /*Codigo de retorno caso de errado o redirect*/ XDP_DROP);
        if( bpf_minha_func(*ptr, 10) < 0) {
            bpf_printk("Erro ao enviar sinal!");
            return XDP_DROP;
        }
        return ret_final; //bpf_redirect_map(&xsk_map, key, /*Codigo de retorno caso de errado o redirect*/ XDP_PASS);
    }
    else{
    //bpf_printk("XDP:Outro tipo de pkt sendo passado!");
    return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";

/*********************************************************************************************************************************************************/

// Trocar isso
#define LOCALHOST_IPV4 16777343 // 127.0.0.1 in network byte order

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 4);
    __type(key, int);
    __type(value, int);
   // __uint(pinning, LIBBPF_PIN_BY_NAME);
} sock_ops_map SEC(".maps");


//struct {
//    __uint(type, BPF_MAP_TYPE_ARRAY);
//    __uint(max_entries, 4);
//    __type(key, int);
//    __type(value, int);
//   // __uint(pinning, LIBBPF_PIN_BY_NAME);
//} temp SEC(".maps");

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
SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg){
    //bpf_printk("ENTROU NO PROGRAMA sk_msg");

    int chave_fil = 1, chave_pai=0, retorno;
    __u64 *ptr;

    //ptr = bpf_map_lookup_elem(&temp , &chave); 
    //bpf_printk("ip local --> ");
    //print_ip(bpf_ntohl(msg->local_ip4 ));
    //bpf_printk("ip remote--> ");
    //print_ip(bpf_ntohl(msg->remote_ip4));
    // bpf_printk("<2>Deu trigger| ip remoto:%s | ip local:%s\n", bpf_ntohl(msg->remote_ip4),
    //                                                        bpf_ntohl(msg->local_ip4));

    // 10.10.10.1 --> 168430081
    // 10.10.10.2 --> 168430082
    // 20.20.20.1 --> 336860161
    // 20.20.20.2 --> 336860162
    if (bpf_ntohl(msg->remote_ip4) == 336860161){
    //if (bpf_ntohl(msg->remote_ip4) == 168430081){
        retorno = bpf_msg_redirect_map(msg, &sock_ops_map, chave_pai, BPF_F_INGRESS);
    }
    else if (bpf_ntohl(msg->remote_ip4) == 336860162){
        retorno = bpf_msg_redirect_map(msg, &sock_ops_map, chave_fil, BPF_F_INGRESS);
    }
        
    if (retorno != SK_PASS){
        bpf_printk("sk_msg:Erro no bpf_msg_redirect_map\n");   
        return SK_DROP;
    }

    return retorno;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

