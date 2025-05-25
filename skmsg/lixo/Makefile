
CC=gcc
CL=clang

all: bpf client server
	@echo "\n +++ compilacao feita +++"

bpf: ebpf.c
	$(CL) -g -O2 -target bpf -c ebpf.c 
	sudo bpftool gen skeleton ebpf.o > ebpf.skel.h 

client: client.c packet.h
	$(CC) $< -o $@ -lbpf

server: server.c packet.h
	$(CC) $< -o $@ -lbpf

clean:
	rm *.o server client
