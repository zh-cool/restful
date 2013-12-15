/*
 * =====================================================================================
 *
 *       Filename:  log.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  12/04/2013 09:59:02 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  austin
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "ezxml.h"
#include "xmlerror.h"
#include "service.h"
#include "util.h"

static int get_sys_log(int client)
{
        char xml[XMLLEN*17] = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                              "<LOG>"
                                "<MSG>"; //</MSG>
                              //"</LOG>;
        char line[XMLLEN] = {0};
        int pos = strlen(xml), len=0;

        FILE *fp = popen("/sbin/logread", "r");
        if(fp==NULL){
                return response_state(client, SYS_ERR, strerror(errno));
        }

        while(fgets(line, sizeof(line), fp)){
                //len = snprintf(xml+pos, sizeof(xml)-pos, "%s\n", line);
                len = cov2xml(xml+pos, line, strlen(line));
                pos += len;
        }
        strcat(xml, "</MSG></LOG>");

        write(client, xml, strlen(xml));
        return 0;
}

static int get_kernel_log(int client)
{
        char xml[XMLLEN*17] = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                              "<LOG>"
                                "<MSG>"; //</MSG>
                              //"</LOG>;
        char line[XMLLEN] = {0};
        int pos = strlen(xml), len=0;

        FILE *fp = popen("/bin/dmesg", "r");
        if(fp==NULL){
                return response_state(client, SYS_ERR, strerror(errno));
        }

        while(fgets(line, sizeof(line), fp)){
                len = cov2xml(xml+pos, line, strlen(line));
                pos += len;
        }
        strcat(xml, "</MSG></LOG>");

        write(client, xml, strlen(xml));
        return 0;

        return 0;
}

int get_log_server(int client, char *ibuf, int len, char *torken)
{
        if(ibuf && !strcmp(ibuf, "/syslog")){
                return get_sys_log(client);
        }

        if(ibuf && !strcmp(ibuf, "/kerlog")){
                return get_kernel_log(client);
        }

        return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
        return 0;
}
