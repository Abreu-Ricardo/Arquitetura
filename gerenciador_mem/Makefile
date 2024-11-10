
$(CC) = gcc

produtor: consumidor rb_produtor rb_consumidor ptr
	$(CC) produtor.c ../bib/teste_bib.c -lbpf -lxdp -o produtor

consumidor: 
	$(CC) consumidor.c ../bib/teste_bib.c -lbpf -lxdp -o consumidor

rb_produtor: 
	$(CC) rb_produtor.c ../bib/teste_bib.c -lbpf -lxdp -o rb_produtor 

rb_consumidor:
	$(CC) rb_consumidor.c ../bib/teste_bib.c -lbpf -lxdp -o rb_consumidor

ptr:
	$(CC) ptr_produtor.c    ../bib/teste_bib.c -lbpf -lxdp -o ptr_produtor
	$(CC) ptr_consumidor.c  ../bib/teste_bib.c -lbpf -lxdp -o ptr_consumidor

clean:
	rm consumidor produtor rb_consumidor rb_produtor ptr_produtor ptr_consumidor
