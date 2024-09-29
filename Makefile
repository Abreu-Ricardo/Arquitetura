
#**************#
$(CC) = gcc
CL = clang
DIR = $(shell pwd)

kern: loader
	$(CL) -g -O2 -target bpf -c ./eBPF/espaco_kernel.c

loader: teste_bib.o loader.o gerenciador
	$(CC) ./bib/teste_bib.o loader.o -lbpf -lxdp -o loader

loader.o: teste_bib.o
	$(CC) -c loader.c

teste_bib.o: 
	make -C ./bib/

gerenciador:
	make -C ./gerenciador_mem/

clean:
	rm loader
	rm *.o 
	rm ./bib/*.o 
	make clean -C ./gerenciador_mem/


