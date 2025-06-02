
#**************#
# Compiladores
CC = gcc
CL = clang

# SOURCE codes
SOURCE_BPF = skmsg_kern.bpf.c kern_teste_sk.bpf.c 
SOURCE_C   = pkt_ping_2process.c

OBJETOS_BPF     = $(SOURCE_BPF:bpf.c=bpf.o)
OBJETOS_C       = $(SOURCE_C:.c=)
OBJETOS_LIB_BPF = $(OBJETOS_BPF:bpf.o=skel.h)

# FLAGS
BPF_FLAGS = -g -O2 -target bpf -c 
C_FLAGS   = -lbpf -lxdp -lpthread -g
GERA_SKEL = bpftool gen skeleton

# skeleton libs
LIBS = skmsg_kern.skel.h 
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

bpf: $(SOURCE_BPF) 
	$(CL) $(BPF_FLAGS) $^

skel: $(OBJETOS_BPF)
	@#$(GERA_SKEL) $^ > $(LIBS)

	@$(foreach i, $^, $(GERA_SKEL) $i > $(i:.bpf.o=.skel.h);)
	
	@echo -e 'Skeletons gerados...\n'
	@#sudo bpftool prog load ./signal_monitor.bpf.o /sys/fs/bpf/signal_monitor type tracepoint


user: pktping_2proc  pktpoll
	@echo -e '$^ criados...'

pktping_2proc: pkt_ping_2process.c 
	$(CC) -pg $< -o $@ $(C_FLAGS)

pktpoll: pktpoll_ping_2process.c 
	$(CC) -pg $< -o $@ $(C_FLAGS)

teste: teste_sk.c
	$(CC) -pg $< -o $@ $(C_FLAGS)


#.PHONY: clean
clean:
	@sudo rm $(OBJETOS_BPF)  pktping_2proc pktpoll
	@sudo rm *.skel.h
	@#sudo rm /sys/fs/bpf/signal_monitor
	@#sudo bpftool prog show
	@#echo -e '\nProgramas removidos...'

