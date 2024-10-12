
$(CC) = gcc

produtor: consumidor rb_produtor rb_consumidor
	$(CC) produtor.c ../bib/teste_bib.c -lbpf -lxdp -o produtor

consumidor: 
	$(CC) consumidor.c ../bib/teste_bib.c -lbpf -lxdp -o consumidor

rb_produtor: 
	$(CC) rb_produtor.c ../bib/teste_bib.c -lbpf -lxdp -o rb_produtor 

rb_consumidor:
	$(CC) rb_consumidor.c ../bib/teste_bib.c -lbpf -lxdp -o rb_consumidor

clean:
	rm consumidor produtor rb_consumidor rb_produtor
