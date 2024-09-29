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

int remove_ebpf(char caminho_prog[],struct info_ebpf *infos);


int le_mapa(struct info_ebpf *infos);
int atualiza_mapa(char caminho_prog[], char nome_mapa[], __u64 *valor, struct info_ebpf *infos);

#endif // MYLIB_H
