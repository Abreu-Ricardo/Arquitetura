
CC=gcc
CL=clang

all: bpf client server
	@echo "\n +++ compilacao feita +++"

bpf: sk_msg_kern.c
	$(CL) -g -O2 -target bpf -c sk_msg_kern.c 
	@#sudo bpftool gen skeleton ebpf.o > ebpf.skel.h 

client: sk_msg_client.c 
	$(CC) $< -o $@ -lbpf

server: sk_msg_user.c 
	$(CC) $< -o $@ -lbpf

clean:
	rm *.o client server
