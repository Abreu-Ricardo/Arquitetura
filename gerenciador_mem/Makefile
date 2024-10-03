

$(CC) = gcc


produtor: consumidor
	$(CC) produtor.c ../bib/teste_bib.c -lbpf -lxdp -o produtor

consumidor: 
	$(CC) consumidor.c ../bib/teste_bib.c -lbpf -lxdp -o consumidor


clean:
	rm consumidor produtor
