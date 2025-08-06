CC = gcc
CL = clang

# SOURCE codes
SOURCE_BPF = xsk_kern.bpf.c
SOURCE_C   = capta_sinal.c

OBJETOS_BPF     = $(SOURCE_BPF:bpf.c=bpf.o)
OBJETOS_C       = $(SOURCE_C:.c=)
OBJETOS_LIB_BPF = $(OBJETOS_BPF:bpf.o=skel.h)

# FLAGS
BPF_FLAGS = -g -O2 -target bpf -c
C_FLAGS   = -lbpf
GERA_SKEL = bpftool gen skeleton

LIBS = signal_monitor.skel.h sigsnoop.skel.h teste_tc.skel.h
DIR = $(shell pwd)

all: bpf skel receiver sender capta_sinal

bpf: $(SOURCE_BPF)
	$(CL) $(BPF_FLAGS) $^

skel: $(OBJETOS_BPF)
	@$(foreach i, $^, $(GERA_SKEL) $i > $(i:.bpf.o=.skel.h);)
	@echo -e 'Skeletons gerados...\n'
	@#sudo bpftool prog load ./signal_monitor.bpf.o /sys/fs/bpf/signal_monitor type tracepoint

capta_sinal: capta_sinal.c
	$(CC) $^ $(C_FLAGS) -o $@

receiver: receiver.c
	$(CC) $^ -o $@

sender: sender.c
	$(CC) $^ -o $@


clean:
	rm receiver sender
	sudo rm $(OBJETOS_BPF) $(OBJETOS_C) $(OBJETOS_LIB_BPF)
