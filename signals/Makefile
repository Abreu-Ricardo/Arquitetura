
#**************#
# Compiladores
CC = gcc
CL = clang

# SOURCE codes
SOURCE_BPF = signal_monitor.bpf.c sigsnoop.bpf.c teste_tc.bpf.c
SOURCE_C   = signal_monitor.c meu_loader.c

OBJETOS_BPF     = $(SOURCE_BPF:bpf.c=bpf.o)
OBJETOS_C       = $(SOURCE_C:.c=.o)
OBJETOS_LIB_BPF = $(OBJETOS_BPF:bpf.o=skel.h)

# FLAGS
BPF_FLAGS = -g -O2 -target bpf -c 
C_FLAGS = -lbpf
GERA_SKEL = bpftool gen skeleton

# skeleton libs
LIBS = signal_monitor.skel.h sigsnoop.skel.h teste_tc.skel.h

DIR = $(shell pwd)

all: kern skel $(SOURCE_C)
#all: $(OBJETOS_BPF) $(OBJETOS_C) 
	@echo -e '\n +++ Compilação pronta! +++'

kern: $(SOURCE_BPF)
#$(OBJETOS_BPF): $(SOURCE_BPF)
	$(CL) $(BPF_FLAGS) $(SOURCE_BPF)
	@echo -e '-->$(OBJETOS_LIB_BPF)'
	@#$(CL) $(BPF_FLAGS) signal_monitor.bpf.c -o signal_monitor.bpf.o
	@#$(CL) $(BPF_FLAGS) sigsnoop.bpf.c -o sigsnoop.bpf.o
	@#$(CL) $(BPF_FLAGS) teste_tc.c -o teste_tc.o

skel: $(OBJETOS_BPF)
	@#$(GERA_SKEL) $(OBJETOS_BPF) > $(OBJETOS_LIB_BPF) #$(LIBS)
	
	@$(foreach i, $(OBJETOS_BPF), $(GERA_SKEL) $i > $(i:.bpf.o=.skel.h);)

	@#$(GERA_SKEL) signal_monitor.bpf.o > signal_monitor.skel.h
	@#$(GERA_SKEL) sigsnoop.bpf.o       > sigsnoop.skel.h
	@#$(GERA_SKEL) teste_tc.o           > teste_tc.skel.h
	
	@#sudo bpftool prog load ./signal_monitor.bpf.o /sys/fs/bpf/signal_monitor type tracepoint

#user: %.c 
$(SOURCE_C): *.c 
	#@$(CC) $@ $(C_FLAGS) -o $<
	
	$(foreach i, $(SOURCE_C), $(CC) $(C_FLAGS) $i -o $(OBJETOS_C);)
	#$(CC) meu_loader.c     -o meu_loader     $(C_FLAGS) 
	#$(CC) signal_monitor.c -o signal_monitor $(C_FLAGS)

%.o: %.c
	$(CC) $(C_FLAGS) -c $< -o $@

clean:
	#sudo rm /sys/fs/bpf/signal_monitor

	sudo rm *.o
	sudo rm *.skel.h
	sudo bpftool prog show
	@echo -e '\nProgramas removidos...'

