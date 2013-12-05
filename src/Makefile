CC = gcc

CFLAGS += -g -Wall 

LDFLAGS += -levent -liwinfo

ALL:cgi.cgi server

obj = server.o directory.o network.o  ezxml.o route_server.o urldecode.o  xmlerror.o util.o wireless.o software.o dhcp.o log.o time.o

cgi.cgi:cgi.o ezxml.o
	$(CC) -o $@ $^ 
server: $(obj)
	$(CC) -o $@ $(obj) $(LDFLAGS)
clean:
	rm -f *.o cgi.cgi server
