
CC = gcc



all: server client udp tcp latencia loop

server: server.c 
	$(CC) $^ -o $@
client: client.c 
	$(CC) $^ -o $@

udp: udp_sender udp_receiver
udp_sender: udp_send.c
	$(CC) $^ -o $@ 
udp_receiver: udp_receiver.c
	$(CC) $^ -o $@ 

tcp: tcp_sender tcp_receiver
tcp_sender: tcp_send.c
	$(CC) $^ -o $@ 
tcp_receiver: tcp_receiver.c
	$(CC) $^ -o $@ 


latencia: t_envia t_recebe
t_envia: t_envia.c
	$(CC) $^ -o $@ 
t_recebe: t_recebe.c
	$(CC) $^ -o $@ 

loop: teste_loop.c
	$(CC) $^ -o $@


clean:
	rm server client udp_receiver udp_sender t_envia t_recebe loop tcp_sender tcp_receiver
