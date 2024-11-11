

$(CC) = gcc
CL = clang

compilacao: kern.o user.o

kern.o:
	$(CL) -g -target bpf -O2 -c prog_kern.c
	$(CL) -g -target bpf -O2 -c xsk_kern.c

user.o:
	$(CC) prog_user.c ../bib/teste_bib.c -lbpf -lxdp -o user.o
	$(CC) xsk_user.c -o user_xdp -lbpf -lxdp

clean:
	rm *.o
	rm user_xdp
