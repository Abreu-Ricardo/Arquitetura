
#**************#
# Compiladores
CC = gcc
CL = clang

# SOURCE codes
SOURCE_BPF = xsk_kern.bpf.c xdp_test.bpf.c 
SOURCE_C   = signal_ping_2process.c loader_xdp.c 

OBJETOS_BPF     = $(SOURCE_BPF:bpf.c=bpf.o)
OBJETOS_C       = $(SOURCE_C:.c=)
OBJETOS_LIB_BPF = $(OBJETOS_BPF:bpf.o=skel.h)

# FLAGS
BPF_FLAGS = -g -O2 -target bpf -c 
C_FLAGS = -lbpf -lxdp -lpthread
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


user: signalping_2proc loader_xdp pollping_2proc pktping_2proc mysignal_2proc
	@echo -e '$^ criados...'

signalping_2proc: signal_ping_2process.c 
	$(CC) $< -o $@ $(C_FLAGS)

loader_xdp: loader_xdp.c
	$(CC) $< -o $@ $(C_FLAGS)

pollping_2proc: poll_ping_2process.c
	$(CC) $<  -o $@ $(C_FLAGS)

pktping_2proc: pkt_ping_2process.c
	$(CC) $< -o $@ $(C_FLAGS)

mysignal_2proc: mysignal_2proc.c
	$(CC) $< -o $@ $(C_FLAGS)



#.PHONY: clean
clean:
	@sudo rm $(OBJETOS_BPF) loader_xdp signalping_2proc pollping_2proc pktping_2proc
	@sudo rm *.skel.h
	@#sudo rm /sys/fs/bpf/signal_monitor
	@#sudo bpftool prog show
	@#echo -e '\nProgramas removidos...'

