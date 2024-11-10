

$(CC) = gcc

user: kern
	$(CC) espaco_usuario.c ../bib/teste_bib.c -lbpf -lxdp -o user 

kern:
	clang -g -O2 -target bpf -c espaco_kernel.c 

clean:
	rm *.o

