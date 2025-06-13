
CC=gcc
CL=clang

BPF_FLAGS = -g -O2 -target bpf -c
C_FLAGS   = -lbpf -lxdp -lpthread -g
GERA_SKEL = bpftool gen skeleton

##############################
SOURCE_BPF = xsk_kern.bpf.c
SOURCE_C   = pkt_ping_2process.c.c

#############################
OBJETOS_BPF     = $(SOURCE_BPF:bpf.c=bpf.o)
OBJETOS_C       = $(SOURCE_C:.c=)
OBJETOS_LIB_BPF = $(OBJETOS_BPF:bpf.o=skel.h)


###################################################
all: bpf skel udp server client

bpf: $(SOURCE_BPF) *.bpf.c
	$(CL) $(BPF_FLAGS) $^
skel: $(OBJETOS_BPF)
	@#$(GERA_SKEL) $^ > $(LIBS)
	@$(foreach i, $^, $(GERA_SKEL) $i > $(i:.bpf.o=.skel.h);)
	@echo -e 'Skeletons gerados...\n'

udp: pkt_ping_2process.c commons.c
	$(CC) $^ -o $@ $(C_FLAGS)

server: server.c
	$(CC) $< -o $@
client: client.c
	$(CC) $< -o $@

clean: 
	rm server client udp $(OBJETOS_BPF) 
