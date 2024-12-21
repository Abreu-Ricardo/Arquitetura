

$(CC) = gcc
CL = clang

compilacao: kern.o user.o

kern.o:
	$(CL) -g -target bpf -O2 -c prog_kern.c
	$(CL) -g -target bpf -O2 -c xsk_kern.c

shm: 
	$(CC) prog_user.c ../bib/teste_bib.c -lbpf -lxdp -o user
	@echo "teste echo"

user.o:
	$(CC) escreve_reply_outro_container.c  -o reply_container -lbpf -lxdp -g
	$(CC) xsk_user.c  -o user_xdp -lbpf -lxdp -g
	$(CC) reply_ping_thread.c    -o thread_reply -lbpf -lxdp -lpthread -g
	$(CC) reply_ping_2process.c  -o reply_2process -lbpf -lxdp -g

clean:
	rm *.o
	rm user_xdp
	rm thread_reply
	rm reply_2process
	rm reply_container
