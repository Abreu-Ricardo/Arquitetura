
#**************#
# Compiladores
CC = gcc
CL = clang

# SOURCE codes
SOURCE_BPF = signal_monitor.bpf.c sigsnoop.bpf.c teste_tc.bpf.c
SOURCE_C   = signal_monitor.c meu_loader.c

OBJETOS_BPF     = $(SOURCE_BPF:bpf.c=bpf.o)
OBJETOS_C       = $(SOURCE_C:.c=)
OBJETOS_LIB_BPF = $(OBJETOS_BPF:bpf.o=skel.h)

# FLAGS
BPF_FLAGS = -g -O2 -target bpf -c 
C_FLAGS = -lbpf
GERA_SKEL = bpftool gen skeleton

# skeleton libs
LIBS = signal_monitor.skel.h sigsnoop.skel.h teste_tc.skel.h
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


user: signal_monitor meu_loader envia_sinal capta_sinal udp
	@echo -e 'signal_monitor, meu_loader, envia_sinal e capta_sinal criado...'
signal_monitor: signal_monitor.c 
	$(CC) $< -o $@ $(C_FLAGS)
meu_loader: meu_loader.c
	$(CC) $< -o $@ $(C_FLAGS)
envia_sinal: envia_sinal.c
	$(CC) $< -o $@ $(C_FLAGS)
capta_sinal: capta_sinal.c
	$(CC) $< -o $@ $(C_FLAGS)

udp: send_pkt recv_pkt
	@echo -e 'send_pkt e recv_pkt prontos...\n'
send_pkt: send_pkt.c
	$(CC) $< -o $@ 
recv_pkt: recv_pkt.c
	$(CC) $< -o $@ 


#.PHONY: clean
clean:
	@#sudo rm /sys/fs/bpf/signal_monitor
	sudo rm $(OBJETOS_BPF) $(OBJETOS_C) $(OBJETOS_LIB_BPF)
	sudo rm send_pkt recv_pkt envia_sinal capta_sinal
	@#sudo bpftool prog show
	@#echo -e '\nProgramas removidos...'

