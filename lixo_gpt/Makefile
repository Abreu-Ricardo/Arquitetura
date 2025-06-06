

CL=clang
CC=gcc


all: bpf xdp_user

bpf: xdp_prog_kern.c
	$(CL) -g -O2 -target bpf -c $^

xdp_user: xdp_user.c
	$(CC) $< -lbpf -lxdp -o $@


clean:
	rm *.o xdp_user
