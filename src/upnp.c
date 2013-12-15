/*
 * =====================================================================================
 *
 *       Filename:  upnp.c
 *
 *    Description:  :upnp
 *
 *        Version:  1.0
 *        Created:  12/09/2013 02:36:13 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include "xmlerror.h"
#include "service.h"
#include "util.h"
#include "ezxml.h"

int get_upnp_server(int client, char *ibuf, int len, char *torken)
{
        if(ibuf){
                return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
        }

        char *ufmt = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                     "<UPNP>"
                        "<ENABLED>%d</ENABLED>"
                     "</UPNP>";

        char xml[XMLLEN]={0};
        int enabled = 0;

        enabled = atoi(uci_get_cfg("upnpd.config.enable_upnp",
                                xml,
                                sizeof(xml)
                                )
                        );
        snprintf(xml, sizeof(xml), ufmt, enabled);

        write(client, xml, strlen(xml));
        return 0;
}

int post_upnp_server(int client, char *ibuf, int len, char *torken)
{
        if(torken){
                return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
        }

        ezxml_t root = NULL, enabled=NULL;

        root = ezxml_parse_str(ibuf, len);
        if(!root){
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }
        if(root && *ezxml_error(root)) {
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

        enabled = ezxml_child(root, "ENABLED");

        if(enabled){
                uci_set_cfg("upnpd.config.enable_natpmp", enabled->txt);
                uci_set_cfg("upnpd.config.enable_upnp", enabled->txt);
                system("/sbin/uci commit");
                system("/etc/init.d/miniupnpd restart");
        }else{
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }
        return 0;
}
