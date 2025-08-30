#**************#
# Compiladores
CC = gcc
CL = clang

# SOURCE codes
SOURCE_BPF = xsk_kern.bpf.c
SOURCE_C   = gateway.c 

OBJETOS_BPF     = $(SOURCE_BPF:bpf.c=bpf.o)
OBJETOS_C       = $(SOURCE_C:.c=)
OBJETOS_LIB_BPF = $(OBJETOS_BPF:bpf.o=skel.h)

# FLAGS
BPF_FLAGS = -g -O2 -target bpf -c 
C_FLAGS   = -lbpf 
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

all: bpf skel user
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo -e '\n+++ Compilação pronta! +++'

bpf: $(SOURCE_BPF)
	$(CL) $(BPF_FLAGS) $^

skel: $(OBJETOS_BPF)
	@$(foreach i, $^, $(GERA_SKEL) $i > $(i:.bpf.o=.skel.h);)
	@echo -e 'Skeletons gerados...\n'
	@#sudo bpftool prog load ./signal_monitor.bpf.o /sys/fs/bpf/signal_monitor type tracepoint


user: gateway nf
	@echo -e 'gateway, nf criados...'

gateway: gateway.c  
	$(CC) $< -o $@ $(C_FLAGS)

nf: nf.c  
	$(CC) $< -o $@ $(C_FLAGS)

#.PHONY: clean
clean:
	sudo rm $(OBJETOS_BPF) $(OBJETOS_C) $(OBJETOS_LIB_BPF)
	@#sudo bpftool prog show
