#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <stddef.h>
#include "ezxml.h"
#include "encry.h"

#define GATEWAY_SERVER_PATH     "/tmp/gateway"
#define ROUTE_SERVER_PATH       "/tmp/route"

#define GATEWAY_PREFIX          "/app/gateway"
#define ROUTE_PREFIX            "/app/route"

char *xmls = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?> \
<CATALOG>\
        <CD>\
                <TITLE>Empire Burlesque</TITLE>\
                <ARTIST>Bob Dylan</ARTIST>\
                <COUNTRY>USA</COUNTRY>\
                <COMPANY>Columbia</COMPANY>\
                <PRICE>10.90</PRICE>\
                <YEAR>1985</YEAR>\
        </CD>\
</CATALOG>";

char *errfmt = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>"
                "<ERROR>"
                "<CODE>%d</CODE>"
                "<MESSAGE>CGI</MESSAGE>"
                "</ERROR>";

char inbuf[1024*1024];
char outbuf[1024*1024];

FILE *fp = NULL;

void response_state(int err)
{
        printf(errfmt, err);
        exit(1);
}

#define CLI_PATH    "/tmp/cgi"

int IPC_SendMsg(const char *ibuf, char *obuf, int length, char *spath)
{
        int fd=0, len=0, pos=0, n_write=0;
        struct sockaddr_un saddr, un;

        fd = socket(AF_UNIX, SOCK_STREAM, 0);

        memset(&un, 0, sizeof(un));
        un.sun_family = AF_UNIX;
        sprintf(un.sun_path, "%s%05d", CLI_PATH, getpid());
        len = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);

        unlink(un.sun_path);        //  in case it already exists
        if (bind(fd, (struct sockaddr *)&un, len) < 0) {
                fprintf(fp, "error:%s\n", strerror(errno));
                return 101;
        }

        bzero(&saddr, sizeof(saddr));
        saddr.sun_family = AF_UNIX;
        strcpy(saddr.sun_path, spath);
        len = offsetof(struct sockaddr_un, sun_path) + strlen(spath);

        if(connect(fd, (struct sockaddr*)&saddr, len) < 0){
                close(fd);
                return 100;
        }

        pos = 0;
        len = strlen(ibuf);
        while(len){
                if((n_write=write(fd, ibuf+pos, len-pos)) < 0){
                        close(fd);
                        return 107;
                }
                pos += n_write;
                len -= n_write;
        }

        pos = 0;
        while((len=read(fd, obuf+pos, length-pos))){
                if(len < 0){
                        close(fd);
                        return 103;
                }
                pos += len;
                if(length <= pos){
                        return 3;
                }
        }

        obuf[pos] = 0;
        close(fd);
        unlink(un.sun_path);
        return 0;
}

int main(int argc, char **argv)
{
        char *method=NULL, *qstr=NULL, *length=NULL, *ptr=NULL;
        int len=0, pos=0, ret=0, n_content=0, n_query;
        char saddr[PATH_MAX];
        ezxml_t xml=NULL;

        fp = fopen("logg", "w");
        system("env > log");
        printf("Content-type:application/xml\n\n");

        method = getenv("REQUEST_METHOD");
        if(method && !strcmp(method, "POST")){
                length = getenv("CONTENT_LENGTH");
                n_content = length ? atoi(length) : 0;
                qstr = getenv("QUERY_STRING");
                n_query = qstr ? strlen(qstr) : 0;

                if((n_content <= 0) || (n_query <= 0)){
                        response_state(3);
                }

                if(qstr && !strncmp(qstr, ROUTE_PREFIX, strlen(ROUTE_PREFIX))){
                        strncpy(saddr, ROUTE_SERVER_PATH, sizeof(saddr));
                }else if(qstr &&
                        !strncmp(qstr, GATEWAY_PREFIX, strlen(GATEWAY_PREFIX))){
                        strncpy(saddr, GATEWAY_SERVER_PATH, sizeof(saddr));
                }else{
                        response_state(1);
                }

                len = read(0, outbuf, sizeof(outbuf));
                xml = ezxml_parse_str(outbuf, len);

                if(!xml || *ezxml_error(xml)){
                        response_state(4);
                }
                free(ptr);

                len = snprintf(outbuf, sizeof(outbuf), "POST %s\n", qstr);
                pos = snprintf(outbuf+len, sizeof(outbuf)-len, "%s",
                                ptr=ezxml_toxml(xml));
                free(ptr);
                ezxml_free(xml);

                qstr = outbuf+len+pos-1;
                while(isspace(*qstr)){
                        *qstr-- = 0;
                }
                *++qstr = '\n';
                *++qstr = '\n';
                *++qstr = 0;

                ptr = strrchr(outbuf, '<');
                *ptr = 0;
                qstr = strrchr(outbuf, '>');
                *ptr = '<';

                qstr++;
                if(qstr != ptr){
                        while(*ptr){
                                *qstr++ = *ptr++;
                        }
                }

                if((ret=IPC_SendMsg(outbuf, outbuf, sizeof(outbuf), saddr))==0){
                        printf("%s", outbuf);
                }else{
                        response_state(ret);
                }
        }else if(method && !strcmp(method, "GET")){
                qstr = getenv("QUERY_STRING");
                if(!qstr){
                        response_state(1);
                }

                if(!strncmp(qstr, ROUTE_PREFIX, strlen(ROUTE_PREFIX))){
                        strncpy(saddr, ROUTE_SERVER_PATH, sizeof(saddr));
                }else if(!strncmp(qstr,
                                  GATEWAY_PREFIX,
                                  strlen(GATEWAY_PREFIX))){
                        strncpy(saddr, GATEWAY_SERVER_PATH, sizeof(saddr));
                }else{
                        fclose(fp);
                        response_state(1);
                }
                snprintf(inbuf, sizeof(inbuf), "GET %s\n\n", qstr);

                if((ret=IPC_SendMsg(inbuf, outbuf, sizeof(outbuf), saddr))){
                        response_state(ret);
                }else{
                        printf("%s", outbuf);
                        fprintf(fp, "recive:%s\n", outbuf);
                }
        }else{
                response_state(1000);
        }

        fclose(fp);
        return 0;
}
