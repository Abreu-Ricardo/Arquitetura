
#**************#
# Compiladores
CC = gcc
CL = clang

# SOURCE codes
SOURCE_BPF = xsk_kern.bpf.c
SOURCE_C   =  poll_ping_refatorado.c

OBJETOS_BPF     = $(SOURCE_BPF:bpf.c=bpf.o)
OBJETOS_C       = $(SOURCE_C:.c=)
OBJETOS_LIB_BPF = $(OBJETOS_BPF:bpf.o=skel.h)

# FLAGS
BPF_FLAGS = -g -O2 -target bpf -c 
C_FLAGS = -lbpf -lxdp -lpthread -g
GERA_SKEL = bpftool gen skeleton

# skeleton libs
LIBS = xsk_kern.skel.h
DIR = $(shell pwd)

# Macros usadas
# taget : prerequisite1, prerequisite2
# 		command
# $^ --> lista os prerequisitos passados no target
# $< --> pega o primeiro prerequisito passado no target
# $@ --> nome do target
# $(SOURCE_BPF:bpf.c=bpf.o) --> Pega os nomes da var e troca a extensao bpf.c por bpf.o

all: bpf skel user
	@echo -e '\n+++ Compilação pronta! +++'


bpf: $(SOURCE_BPF) *.bpf.c
	$(CL) $(BPF_FLAGS) $^

skel: $(OBJETOS_BPF)
	@#$(GERA_SKEL) $^ > $(LIBS)

	@$(foreach i, $^, $(GERA_SKEL) $i > $(i:.bpf.o=.skel.h);)
	
	@echo -e 'Skeletons gerados...\n'
	@#sudo bpftool prog load ./signal_monitor.bpf.o /sys/fs/bpf/signal_monitor type tracepoint

user: pollping_ref udp signal
	@echo -e '$^ criados...'

pollping_ref: poll_ping_refatorado.c commons.c
	$(CC) $^   -o $@ $(C_FLAGS)

udp: pkt_ping_2process.c commons.c
	$(CC) $^  -o $@ $(C_FLAGS)

signal: signal_ping_2process.c commons.c
	$(CC) $^  -o $@ $(C_FLAGS)


#.PHONY: clean
clean:
	@sudo rm $(OBJETOS_BPF)  
	@sudo rm *.skel.h udp signal pollping_ref
	@#sudo bpftool prog show
	@#echo -e '\nProgramas removidos...'

