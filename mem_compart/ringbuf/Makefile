#**************#
# Compiladores
CC = gcc
CL = clang

# SOURCE codes
SOURCE_BPF = xsk_kern.bpf.c
SOURCE_C   = shm_test.c ringbuf.c 

OBJETOS_BPF     = $(SOURCE_BPF:bpf.c=bpf.o)
OBJETOS_C       = $(SOURCE_C:.c=)
OBJETOS_LIB_BPF = $(OBJETOS_BPF:bpf.o=skel.h)

# FLAGS
BPF_FLAGS = -g -O2 -target bpf -c 
C_FLAGS   = -lbpf -g 
GERA_SKEL = bpftool gen skeleton

# skeleton libs
LIBS = xsk_kern.bpf.skel.h http.skel.h
DIR = $(shell pwd)

# Macros usadas
# taget : prerequisite1, prerequisite2
# 		command
# $^ --> lista os prerequisitos passados no target
# $< --> pega o primeiro prerequisito passado no target
# $@ --> nome do target
# $(SOURCE_BPF:bpf.c=bpf.o) --> Pega os nomes da var e troca a extensao bpf.c por bpf.o

all: gateway nf envia_sinal
	@echo -e 'Compilacao terminada'

gateway: ringbuf.o shm_test.o
	$(CC) $^ -o gateway

nf: shm_test.o nf.o
	$(CC)  $^ -o $@ 

nf.o: nf.c
	$(CC) -c $^ -o $@ 

ringbuf.o: ringbuf.c
	$(CC) -c $^ -o $@ 

shm_test.o: shm_test.c
	$(CC) -c $^ -o $@ 

envia_sinal: envia_sinal.c
	$(CC) $^ -o $@


#.PHONY: clean
clean:
	@#sudo rm $(OBJETOS_BPF) $(OBJETOS_C) $(OBJETOS_LIB_BPF)
	rm *.o gateway envia_sinal
	@#sudo bpftool prog show
