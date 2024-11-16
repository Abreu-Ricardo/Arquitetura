
#**************#
$(CC) = gcc
CL = clang
DIR = $(shell pwd)

kern: loader_ebpf loader_xdp 
	$(CL) -g -O2 -target bpf -c ./eBPF/espaco_kernel.c

loader_xdp: teste_bib.o
	$(CC) loader_xdp.c  -lbpf -lxdp -o loader_xdp

loader_ebpf: teste_bib.o loader.o gerenciador 
	$(CC) ./bib/teste_bib.o loader_ebpf.o -lbpf -lxdp -o loader_ebpf

loader.o: teste_bib.o
	$(CC) -c loader_ebpf.c

teste_bib.o: 
	make -C ./bib/

gerenciador:
	make -C ./gerenciador_mem/

testes:
	make -C ./testes/

clean:
	rm loader_ebpf loader_xdp
	rm *.o 
	make clean -C ./gerenciador_mem/
	make clean -C ./bib/
	make clean -C ./testes/

