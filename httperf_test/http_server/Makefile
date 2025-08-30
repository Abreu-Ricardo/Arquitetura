


all: server realServer

server: web_server.c
	gcc $^ -o $@ 

realServer: moreReal_http_server.c
	gcc $^ -o $@ -lpthread

clean:
	rm server realServer
