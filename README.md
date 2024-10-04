# Arquitetura
Prototipo da arquitetura

## Para alterar entre exec no host e entre containers
- /bib/teste_bib.c= carrega_ebpf() remove_ebpf() --> alterar o caminho do mapa pinado
- /eBPF/espaco_kernel.c= comentar atributo pinning do mapa
- /gerenciador_mem/consumidor.c= alterar caminho de mapa_fd no qual ele usa para pegar o fd
