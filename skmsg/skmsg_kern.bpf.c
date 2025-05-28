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
//struct {
//        __uint(type, BPF_MAP_TYPE_ARRAY);
//        __uint(max_entries, 1);
//        __type(key, __u32);
//        __type(value, sizeof(pid_t)); 
//    	//__uint(pinning, LIBBPF_PIN_BY_NAME); // atributo para pinnar o mapa em /sys/fs/bpf/
//} mapa_sinal SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} mapa_sock SEC(".maps");


/****************************************************************************/
unsigned char protocol = 0;
void *data; 
void *data_end;

struct ethhdr *eth;
struct iphdr *iph;

static __always_inline int verifica_ip(struct sk_msg_md *ctx){

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
__u32 pkt_global = 0;

SEC("sk_msg")
int prog_socket(struct sk_msg_md *msg){

//SEC("xdp")
//int xdp_prog(struct xdp_md *ctx){
    // Redireciona o pacote para o socket XDP associado no mapa xsk_map
    //int index = ctx->rx_queue_index; //0; // index do socket
    int ret, key = 0; // indice 0 eh para o primeiro socket e 1 para o segundo socket
    
    __u64 *ptr;
    __u64 *ptr_sig;
    __u32 ret_final;
    __u64 ret_func;


    // TODO
    // POPULAR O MAPA_SOCK COM O FD DO SOCKET CRIADO PARA ESPERAR COM recv()

    //uint32_t pid = pid_tgid & 0xFFFFFFFF;
    //uint32_t tgid = pid_tgid >> 32;
    
    //bpf_printk("Process ID: %d, Thread Group ID: %d\n", pid, tgid);


    ret = verifica_ip(msg);
    //ptr = bpf_map_lookup_elem(&mapa_sock, &key);
    //ptr_sig = bpf_map_lookup_elem(&tempo_sig, &pkt_global);

    //if (ptr == NULL){
	//    bpf_printk("Erro ao acessar o mapa_sinal");
	//    return XDP_DROP;
    //}

    // Se for pacote UDP == 17
    //if( ret == 17){
    if( ret == 1 /*&& ptr_sig != NULL*/){
    //if (ret == 17){

        ret_final = bpf_redirect_map(&mapa_sock, key, /*Codigo de retorno caso de errado o redirect*/ SK_DROP);


       
        return ret_final; //bpf_redirect_map(&xsk_map, key, /*Codigo de retorno caso de errado o redirect*/ XDP_PASS);
    }
    else{
        bpf_printk("Erro ao acessar o mapa_sinal!!!");
        return XDP_DROP;
    }

    //bpf_printk("Pkt n foi redirecionado! %d\n", ret);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
