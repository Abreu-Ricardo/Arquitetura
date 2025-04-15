
CC = gcc



all: server client udp

server: server.c 
	$(CC) $^ -o $@

udp: udp_sender udp_receiver

udp_sender: udp_send.c
	$(CC) $^ -o $@ 

udp_receiver: udp_receiver.c
	$(CC) $^ -o $@ 

client: client.c 
	$(CC) $^ -o $@


clean:
	rm server client udp_receiver udp_sender
