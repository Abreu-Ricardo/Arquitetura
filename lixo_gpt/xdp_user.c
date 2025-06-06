// xdp_user.c

#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <linux/if_link.h>
//#include <bpf/xsk.h>
#include <xdp/xsk.h>
#include <xdp/libxdp.h>
#include <sys/resource.h>


#define IFACE "veth2"
#define NUM_SOCKS 1
#define NUM_FRAMES 4096
#define FRAME_SIZE 2048

struct xsk_socket_info {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_cons cq;
    struct xsk_ring_prod fq;
    struct xsk_ring_prod tx;
    struct xsk_umem *umem;
    void *umem_area;
};

struct xsk_umem_config umem_cfg = {
    .fill_size  = NUM_FRAMES,
    .comp_size  = NUM_FRAMES,
    .frame_size = FRAME_SIZE,
    .frame_headroom = 0,
    //.flags = 0,
};

struct xsk_socket_config cfg = {
    .rx_size = 2048,
    .tx_size = 2048,
    .xdp_flags    = XDP_FLAGS_SKB_MODE /*XDP_FLAGS_DRV_MODE*/ ,
    .bind_flags   = XDP_COPY,
    .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
};

int load_xdp_program(const char *iface, struct bpf_object **obj_out, int *prog_fd_out) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd;
    int err;

    obj = bpf_object__open_file("xdp_prog_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "xdp_sock_prog");
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        return 1;
    }

    int ifindex = if_nametoindex(iface);
    //err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    
    //err = bpf_xdp_attach(ifindex, prog_fd, /*XDP_FLAGS_DRV_MODE*/ XDP_FLAGS_SKB_MODE, NULL); 
    //err = xdp_program__attach( xdp_program__from_bpf_obj( obj, "xdp") , ifindex, XDP_MODE_NATIVE, 0);
    struct bpf_link *prog_link;
    prog_link = bpf_program__attach_xdp( prog , ifindex ); 
    if (prog_link == NULL) {
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
        return 1;
    }

    printf("\nAQUII passou do attach\n");

    *obj_out = obj;
    *prog_fd_out = prog_fd;
    return 0;
}

int setup_xsk_socket(struct xsk_socket_info *xsk, const char *iface, int queue_id, int xskmap_fd) {
    int ret;

    // Aumentando o limite de recurso que o processo pode usar
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("Erro ao configurar limite de memória bloqueada");
        exit(1);
    }

    // Allocate UMEM
    int ret_posix = posix_memalign(&xsk->umem_area, getpagesize(), NUM_FRAMES * FRAME_SIZE);
    if(ret_posix < 0){
        perror("Erro no posix_memalign:");
    }


    //ret = xsk_umem__create(&xsk->umem, xsk->umem_area, NUM_FRAMES * FRAME_SIZE, &xsk->fq, NULL, &umem_cfg);
    ret = xsk_umem__create(&xsk->umem, xsk->umem_area, NUM_FRAMES * FRAME_SIZE, &xsk->fq, &xsk->cq, &umem_cfg);
    if (ret < 0) {
        perror("xsk_umem__create");
        return 1;
    }

    //ret = xsk_socket__create(&xsk->xsk, iface, queue_id, xsk->umem, &xsk->rx, NULL, &cfg);
    ret = xsk_socket__create(&xsk->xsk, iface, 0, xsk->umem, &xsk->rx, &xsk->tx, &cfg);
    if (ret < 0) {
        fprintf(stderr, "xsk_socket__create failed: %s\n", strerror(-ret));
        return 1;
    }

    for (int i = 0; i < NUM_FRAMES; i++) {
        uint32_t idx;
        if (xsk_ring_prod__reserve(&xsk->fq, 1, &idx) != 1)
            break;
        *xsk_ring_prod__fill_addr(&xsk->fq, idx) = i * FRAME_SIZE;
        xsk_ring_prod__submit(&xsk->fq, 1);
    }

    // Update XSKMAP
    ret = bpf_map_update_elem(xskmap_fd, &queue_id, &(int){xsk_socket__fd(xsk->xsk)}, 0);
    if (ret) {
        perror("bpf_map_update_elem");
        return 1;
    }

    return 0;
}

int main(void) {
    struct bpf_object *obj;
    int prog_fd;

    // Load and attach XDP program
    if (load_xdp_program(IFACE, &obj, &prog_fd)) {
        return 1;
    }

    // Get xsks_map fd
    int xskmap_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    if (xskmap_fd < 0) {
        fprintf(stderr, "Failed to find xsks_map\n");
        return 1;
    }

    struct xsk_socket_info socks[NUM_SOCKS] = {0};

    // Create sockets for queues 0 and 1
    for (int i = 0; i < NUM_SOCKS; i++) {
        if (setup_xsk_socket(&socks[i], IFACE, i, xskmap_fd)) {
            return 1;
        }
    }

    // Use recvfrom() on both sockets
    char buf[2048];
    struct sockaddr_xdp addr = {};
    socklen_t addrlen = sizeof(addr);

    printf("Waiting for packets...\n");

    while (1) {
        for (int i = 0; i < NUM_SOCKS; i++) {
            int fd  = xsk_socket__fd(socks[i].xsk);
            int ret = recvfrom(fd, buf, sizeof(buf), 0,
                               (struct sockaddr *)&addr, &addrlen);
            if (ret > 0) {
                printf("Queue %d: got %d bytes\n", i, ret);
            } else if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("recvfrom");
            }
        }
        usleep(1000);
    }

    return 0;
}

