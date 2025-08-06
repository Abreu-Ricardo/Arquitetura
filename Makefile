
#**************#
$(CC) = gcc
CL = clang
DIR = $(shell pwd)

#kern: loader_ebpf loader_xdp loaders testes 
kern: loaders testes.o
	$(CL) -g -O2 -target bpf -c ./eBPF/espaco_kernel.c
	@echo -e 'FIM MAKE...'


loaders: teste_bib.o loader.o gerenciador
	$(CC) ./loaders/loader_xdp.c  -lbpf -lxdp -o loader_xdp
	$(CC) ./bib/teste_bib.o ./loaders/loader_ebpf.o -lbpf -lxdp -o loader_ebpf
	@echo -e 'Make do loader_ebpf concluído...\n'



gerenciador:
	make -C ./gerenciador_mem/
	@echo -e 'Make do diretório gerenciador concluído...\n'

testes.o:
	make -C ./testes/
	@echo -e 'Make do diretório testes concluído...\n'

clean:
	#rm loader_ebpf loader_xdp
	make clean -C ./gerenciador_mem/
	@echo -e 'clean ./gerenciadaor_mem/\n'
	
	make clean -C ./bib/
	@echo -e 'clean ./bib/\n'

	make clean -C ./testes/
	@echo -e 'clean ./testes/\n'
	
	make clean -C ./loaders/
	@echo -e 'clean ./loaders/\n'

