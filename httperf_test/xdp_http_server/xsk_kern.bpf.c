// xdp_program.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // bpf_ntohs()
#include <linux/pkt_cls.h>   // inclui as funcs do TC
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h> // struct ethhdr
#include <linux/ip.h>	    // struct iphr
#include <linux/udp.h>
#include <linux/icmp.h>
#include <stdint.h>
#include <time.h>

#include <netinet/tcp.h>
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
        __uint(max_entries, 2);
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

static __always_inline int verifica_prot(struct xdp_md *ctx){

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

struct tcphdr *tcph;
static __always_inline int tcp_flag(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    // TCP == 6
    //if (iph->protocol != 6)
    //    return -1;

    struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
    if ((void *)(tcph + 1) > data_end)
        return -1;

    // SAFER: read raw flags byte (offset 13 in TCP header)
    __u8 flags = *((__u8 *)tcph + 13);

    if (flags & TH_PUSH) {
        bpf_printk("PSH flag set\n");
        return 1;
    }

    if (flags & TH_SYN)
        bpf_printk("SYN flag set\n");

    if (flags & TH_ACK)
        bpf_printk("ACK flag set\n");

    return 0;
}
//static __always_inline int tcp_flag(struct xdp_md *ctx){
//
//	//void *data = (void *)(long)ctx->data;
//	//void *data_end = (void *)(long)ctx->data_end;
//    data = (void *)(long)ctx->data;
//    data_end = (void *)(long)ctx->data_end;
//    int push_flag = 0;
//
//	eth = data;
//	if (data + sizeof(struct ethhdr) > data_end){
//        	return -1; 
//	}
//
//    if (bpf_ntohs(eth->h_proto) == ETH_P_IP){	
//        iph = data + sizeof(struct ethhdr);
//
//        // Verificar se eh um pacote IP
//
//        // Protocolo do pacote
//        // 1 = ICMP
//        // 6 = TCP
//        // 17 = UDP
//
//        if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){
//            //protocol = iph->protocol;
//
//            tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
//            if(data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) <= data_end){
//
//                bpf_printk("flag_push:%d |flag_syn:%d| flag_ack:%d\n", tcph->psh, tcph->syn, tcph->ack);
//
//                //int temp = (tcph->psh + tcph->ack + tcph->syn + tcph->fin + tcph->rst);
//                if ( tcph->th_flags /*psh*/ & TH_PUSH  ){
//                    bpf_printk("AAAAAAAAAAAAAAAAa\n");
//                    push_flag = 1;
//                }
//            }
//
//        }
//
//    }
//	return push_flag;
//}


/*****************************************************************************/
__u32 pkt_global = 0;

SEC("xdp")
int xdp_prog(struct xdp_md *ctx){
    bpf_printk("Capturou o pkt!\n");
    // Redireciona o pacote para o socket XDP associado no mapa xsk_map
    //int index = ctx->rx_queue_index; //0; // index do socket
    int ret, key = 0; // indice 0 eh para o primeiro socket e 1 para o segundo socket
    
    __u64 *ptr;
    __u64 *ptr_sig;
    __u32 ret_final;
    __u64 ret_func;

    ret = verifica_prot(ctx);
    ptr = bpf_map_lookup_elem(&mapa_sinal, &key);


    if( ptr != NULL ){
        if(ret == 6 /*&& ptr_sig != NULL*/){

            int temp = tcp_flag(ctx);
            bpf_printk("temp: %d\n",temp);
            if( temp != 1 ){ 
                return XDP_PASS; 
            }

            ret_final = bpf_redirect_map(&xsk_map, key, /*Codigo de retorno caso de errado o redirect*/ XDP_DROP);
            //ret_func = bpf_minha_func(*ptr, 10);
            //ret_func = bpf_minha_func(*ptr, 10, &tempo_sig, &pkt_global);
            if( bpf_minha_func(*ptr, 35) /*ret_func*/ < 0 ){
                bpf_printk("Erro ao enviar sinal para o pid");
                return XDP_DROP;
            }

            //pkt_global++; 
            return ret_final; //bpf_redirect_map(&xsk_map, key, /*Codigo de retorno caso de errado o redirect*/ XDP_PASS);
        }
    }
    else{
        bpf_printk("Erro ao acessar o mapa_sinal!!!");
        return XDP_DROP;
    }

    //bpf_printk("Pkt n foi redirecionado! %d\n", ret);
    return XDP_PASS;
}

/*****************************************************************************/


// Define um mapa XSKMAP para o socket AF_XDP
//struct {
//    __uint(type, BPF_MAP_TYPE_ARRAY );
//    __uint(max_entries, 4); 
//    __type(key, __u32);
//    __type(value, __u32);
//} tcp_map SEC(".maps");
//
//
//SEC("tc")
//int tcp_protocol(struct __sk_buff *ctx){
//    // Redireciona o pacote para o socket XDP associado no mapa xsk_map
//    //int index = ctx->rx_queue_index; //0; // index do socket
//    int ret, key = 0; // indice 0 eh para o primeiro socket e 1 para o segundo socket
//    
//    __u64 *ptr;
//    __u64 *ptr_sig;
//    __u32 ret_final;
//    __u64 ret_func;
//
//
//
//    
//}

char _license[] SEC("license") = "GPL";
