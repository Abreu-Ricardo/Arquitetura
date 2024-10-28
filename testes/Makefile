

$(CC) = gcc
CL = clang

compilacao: kern.o user.o

kern.o:
	$(CL) -g -target bpf -O2 -c prog_kern.c
	$(CL) -g -target bpf -O2 -c gepeto_kern.c

user.o:
	$(CC) prog_user.c ../bib/teste_bib.c -lbpf -lxdp -o user.o
	#$(CC) ptr_mem_produtor.c -o ptr_produtor
	#$(CC) ptr_mem_consumidor.c -o ptr_consumidor
	$(CC) gepeto_user.c -o user_xdp -lbpf -lxdp
	$(CC) teste.c -o teste -lbpf -lxdp

clean:
	rm *.o
	rm user_xdp
	rm teste
