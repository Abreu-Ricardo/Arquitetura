

$(CC) = gcc
CL = clang

compilacao: kern.o user.o

kern.o:
	$(CL) -g -target bpf -O2 -c prog_kern.c
	$(CL) -g -target bpf -O2 -c xsk_kern.c

shm: 
	$(CC) prog_user.c ../bib/teste_bib.c -lbpf -lxdp -o user
	@echo "sdfsdf"

user.o:
	$(CC)      xsk_user.c  -o user_xdp -lbpf -lxdp -g
	$(CC) escreve_reply_outro_container.c  -o reply -lbpf -lxdp -g
	$(CC) reply_ping_thread.c  -o thread_reply -lbpf -lxdp -lpthread -g

clean:
	rm *.o
	rm user_xdp
