
#**************#
$(CC) = gcc
CL = clang
DIR = $(shell pwd)

kern: loader
	$(CL) -g -O2 -target bpf -c ../eBPF/espaco_kernel.c

loader: teste_bib.o loader.o
	$(CC) ../bib/teste_bib.o loader.o -lbpf -lxdp -o loader

loader.o: teste_bib.o
	$(CC) -c loader.c

teste_bib.o: 
	make -C ../bib/

clean:
	rm *.o loader
	rm ../bib/*.o


