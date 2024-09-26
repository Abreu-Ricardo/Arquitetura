#ifndef MINHALIB_H

#define MINHALIB_H

#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

typedef struct info_ebpf{
    int prog_fd;
    int mapa_fd;
    int valor_mapa;
    char *nome_mapa;
} info_ebpf;


void carrega_ebpf(char *caminho_prog, char *nome_prog, struct info_ebpf *infos);

int remove_ebpf(struct info_ebpf *infos, struct bpf_object *bpf_obj);


int le_mapa();
int escreve_mapa();

#endif // MYLIB_H
