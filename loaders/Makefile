$(CC) = gcc

loaders.o:
	$(CC) -c loader_ebpf.c -lbpf -o loader_ebpf.o
	$(CC) -c loader_xdp.c  -lbpf -lxdp -o loader_xdp.o

clean:
	rm loader_ebpf.o loader_xdp.o

