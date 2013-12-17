CC = gcc

CFLAGS += -g -Wall 

LDFLAGS += -levent -liwinfo -lcurl -lcrypto

ALL:cgi.cgi server

obj = server.o directory.o network.o  ezxml.o route_server.o\
      urldecode.o  xmlerror.o util.o wutil.o wireless.o software.o\
      dhcp.o log.o time.o system.o upnp.o wclient.o download.o base64.o

cgi.cgi:cgi.o ezxml.o
	$(CC) -o $@ $^ 
server: $(obj)
	$(CC) -o $@ $(obj) $(LDFLAGS)
clean:
	rm -f *.o cgi.cgi server
