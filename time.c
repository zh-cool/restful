/*
 * =====================================================================================
 *
 *       Filename:  time.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  12/04/2013 03:16:42 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include "ezxml.h"
#include "service.h"
#include "util.h"
#include "xmlerror.h"

int get_time_server(int client, char *ibuf, int len, char *torken)
{
	if(ibuf){
		return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
	}

	char *tfmt =	"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
			"<TIME>"
		 		"<CUR_TIME>%d</CUR_TIME>"
				"<CTIME>%s</CTIME>"
				"<TIME_ZONE>%s</TIME_ZONE>"
				"<ZONE_NAME>%s</ZONE_NAME>"
			"</TIME>";

	char xml[XMLLEN] = {0}, tzone[32]={0}, zname[64]={0};


	time_t tm = time(NULL);
	snprintf(xml, sizeof(xml), tfmt, 
			tm, 
			ctime(&tm),
			uci_get_cfg("system.@system[0].timezone", tzone, sizeof(tzone)),
			uci_get_cfg("system.@system[0].zonename", zname, sizeof(zname))
		);

	write(client, xml, strlen(xml));
	return 0;
}

static int check_tserver(ezxml_t tserver)
{
	return 0;
}

static int check_tzone(ezxml_t tzone)
{
	return 0;
}

int post_time_server(int client, char *ibuf, int len, char *torken)
{
	if(torken){
		printf("%s", torken);
		return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
	}
	
	ezxml_t root=NULL, tserver=NULL, tzone=NULL;
	root = ezxml_parse_str(ibuf, len);
	if(!root){
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
	}
        if(root && *ezxml_error(root)) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

	tserver = ezxml_child(root, "TIME_SERVER");
	tzone	= ezxml_child(root, "TIME_ZONE");
	int changed = 0;

	if(tserver){
		if(check_tserver(tserver)){
			return response_state(client, FORMAT_ERR, "Invalid Time server url");
		}
	}

	if(tzone){
		if(check_tzone(tzone)){
			return response_state(client, FORMAT_ERR, "Invalid time zone");
		}
	}

	if(tserver){
		ezxml_t url = ezxml_child(root, "URL");
		char tsurl[XMLLEN]= {0};
		int pos=0, len=0;
		for(; url; url=url->next){
			len = snprintf(tsurl+pos, sizeof(tsurl)-pos, "%s ", url->txt);
			pos += len;
		}
		tsurl[pos-1] = 0;
		uci_set_cfg("system.ntp.server", tsurl);
		changed = 1;
	}

	if(tzone){
		uci_set_cfg("system.@system[0].timezone", tzone->txt);
		changed = 1;
	}

	if(changed){
		system("/sbin/uci commit system");
		system("/sbin/uci get system.@system[0].timezone >/tmp/TZ");
	}
	return 0;
}
