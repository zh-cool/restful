/*
 * =====================================================================================
 *
 *       Filename:  dhcp.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  12/03/2013 09:24:57 AM
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
#include "xmlerror.h"
#include "service.h"
#include "util.h"
#include "ezxml.h"
static int get_dhcp_clients(int client)
{
	char xml[1024] ="<?xml version=\"1.0\" encoding=\"utf-8\"?>""<DHCP>";     //"</DHCP>";

	char *cfmt = 	"<CLIENTS>"
				"<MAC>%s</MAC>"
				"<IP>%s</IP>"
				"<HOSTNAME>%s</HOSTNAME>"
				"<TIME>%s</TIME>"
			"</CLIENTS>";

	FILE *fp = fopen("/var/dhcp.leases", "r");
	if(NULL == fp){
		return response_state(client, SYS_ERR, strerror(errno));
	}

	char line[256] = {0}, ip[INET_ADDRSTRLEN]={0}, mac[32]={0}, name[128]={0};
	time_t time, len=0, pos=0;

	pos = strlen(xml);
	while(fgets(line, sizeof(line), fp)){
		sscanf(line, "%d %s %s %s", &time, mac, ip, name);
		len = snprintf(xml+pos, sizeof(xml)-pos, cfmt, mac, ip, name, ctime(&time));
		pos += len;
	}
	strcat(xml, "</DHCP>");

	write(client, xml, sizeof(xml));
	return 0;
}

static int get_dhcp_config(int client)
{
	char *dfmt = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		     "<DHCP>"
		     	"<ENABLED>%d</ENABLED>"
			"%s"
		     "</DHCP>";

	char *sfmt = "<STATIC>"
			"<MAC>%s</MAC>"
			"<IP>%s</IP>"
		     "</STATIC>";

	char xml[XMLLEN] = {0};
	char slist[XMLLEN] = {0}, host[128] = {0};
	char mac[32] = {0};
	char ip[INET_ADDRSTRLEN+1] = {0};
	int enabled=0, length=0, pos=0, idx=0;

	pos = 0;
	while(1){
		snprintf(host, sizeof(host), "dhcp.@host[%d]", idx);
		uci_get_cfg(host, xml, sizeof(xml));
		if(0 == strlen(xml)){
			break;
		}

		snprintf(host, sizeof(host), "dhcp.@host[%d].mac", idx);
		uci_get_cfg(host, mac, sizeof(mac));

		snprintf(host, sizeof(host), "dhcp.@host[%d].ip", idx);
		uci_get_cfg(host, ip, sizeof(ip));

		length=snprintf(slist+pos, sizeof(slist)-pos, sfmt, mac, ip);
		pos += length;
		idx++;
	}

	uci_get_cfg("dhcp.lan.ignore", xml, sizeof(xml));
	if(0 == strlen(xml)){
		enabled = 1;
	}else{
		enabled = 0;
	}

	snprintf(xml, sizeof(xml), dfmt, enabled, slist);
	write(client, xml, strlen(xml));
	return 0;
}
int get_dhcp_server(int client, char *ibuf, int len, char *torken)
{
	if(ibuf && !strcmp(ibuf, "/config")){
		return get_dhcp_config(client);
	}

	if(ibuf && !strcmp(ibuf, "/clients")){
		return get_dhcp_clients(client);
	}

	return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
}

int check_static_list(ezxml_t slist)
{
	ezxml_t mac=NULL, ip=NULL;
	for(; slist; slist=slist->next){
		mac = ezxml_child(slist, "MAC");
		ip = ezxml_child(slist, "IP");
		if(!ip || !ip->txt[0] || !mac || !mac->txt[0]){
			return 1;
		}
		if(!isip(ip->txt)){
			return 1;
		}
	}
	return 0;
}

int post_dhcp_server(int client, char *ibuf, int len, char *torken)
{
	int changed = 0;
	if(torken){
		return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
	}

	ezxml_t root = NULL, enabled=NULL, slist=NULL, mac=NULL, ip=NULL;

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
		if(!enabled->txt[0])
			ezxml_free(root);
			return response_state(client, FORMAT_ERR, "Invalid ENABLE arg");
	
		int ienabled = atoi(enabled->txt);
		if((ienabled!=0) && (ienabled !=1)){
			ezxml_free(root);
			return response_state(client, FORMAT_ERR, "ENABLE arg 0/1");
		}

		if(ienabled){
			uci_set_cfg("dhcp.lan.ignore", "");
			uci_set_cfg("dhcp.lan.start", "100");
			uci_set_cfg("dhcp.lan.start", "150");
			uci_set_cfg("dhcp.lan.leasetime", "12h");
		}else{
			uci_set_cfg("dhcp.lan.ignore", "1");
			uci_set_cfg("dhcp.lan.start", "");
			uci_set_cfg("dhcp.lan.limit", "");
			uci_set_cfg("dhcp.lan.leasetime", "");
		}
		changed = 1;
	}

	slist = ezxml_child(root, "STATIC");
	if(check_static_list(slist)){
		ezxml_free(root);
		return response_state(client, FORMAT_ERR, "Static List");
	}

	if(slist){
		char host[32];
		while(uci_get_cfg("dhcp.@host[-1]", host, sizeof(host))){
			if(strlen(host)){
				system("/sbin/uci delete dhcp.@host[-1]");
			}else{
				break;
			}
		}

		for(; slist; slist=slist->next){
			mac = ezxml_child(slist, "MAC");
			ip  = ezxml_child(slist, "IP");
			system("/sbin/uci add dhcp host");
			uci_set_cfg("dhcp.@host[-1].mac", mac->txt);
			uci_set_cfg("dhcp.@host[-1].ip", ip->txt);
		}
		changed = 1;
	}

	if(changed){
		system("/sbin/uci commit");
		system("/etc/init.d/network restart");
	}
	
	return 0;
}
