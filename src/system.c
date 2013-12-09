/*
 * =====================================================================================
 *
 *       Filename:  system.c
 *
 *    Description:  :system status and act
 *
 *        Version:  1.0
 *        Created:  12/09/2013 11:36:38 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <dirent.h>
#include <error.h>
#include <ctype.h>
#include "restful.h"
#include "service.h"
#include "ezxml.h"
#include "xmlerror.h"
#include "errno.h"
#include "util.h"

static int get_sys_traffic(int client)
{

	char *tfmt =  "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
			"<SYSTEM>"
				"<TRAFFIC>"
					"%s"
				"</TRAFFIC>"
			"</SYSTEM>";

	char *ifmt =    "<INTERFACE>"
				"<NAME>%s</NAME>"
				"<SEND_BYTES>%d</SEND_BYTES>"
				"<SEND_PKTS>%d</SEND_PKTS>"
				"<RECV_BYTES>%d</RECV_BYTES>"
				"<RECV_PKTS>%d</RECV_PKTS>"
			"</INTERFACE>";

	const char *DEV = "/proc/net/dev";
	FILE *fp = fopen(DEV, "r");
	char line[128] = {0}, name[16]={0};
	
	char xml[XMLLEN*2]={0}, interface[XMLLEN*2]={0};
	uint32_t s_bytes=0, s_pkts=0, r_bytes=0, r_pkts=0, tmp, len=0, pos=0;

	if(!fp){
		return response_state(client, SYS_ERR, strerror(errno));
	}

	fgets(line, sizeof(line), fp);
	fgets(line, sizeof(line), fp);

	pos = 0;
	while(fgets(line, sizeof(line), fp)){
		sscanf(line, "%s %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u %u", name,
				&r_bytes, &r_pkts, &tmp, &tmp, &tmp, &tmp, &tmp, &tmp,
				&s_bytes, &s_pkts, &tmp, &tmp, &tmp, &tmp, &tmp, &tmp
		      );
		name[strlen(name)-1] = 0;
		len = snprintf(interface+pos, sizeof(interface)-pos, ifmt, name, s_bytes, s_pkts, r_bytes, r_pkts);
		pos += len;
	}
	snprintf(xml, sizeof(xml), tfmt, interface);
	write(client, xml, strlen(xml));
	return 0;
}

static int get_sys_basic(int client)
{
	char *bfmt = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		     "<SYSTEM>"
		     	"<NAME>ToMoon</NAME>"
			"<VERSION>OpenWrt Attitude Adjustment 12.09</VERSION>"
			"<MODEL>Atheros DB120 reference board</MODEL>"
		     	"<CTIME>%s</CTIME>"
		     	"<UPTIME>%s</UPTIME>"
		     "</SYSTEM>";
	char xml[XMLLEN]={0}, uptime[128] = {0}, line[128]={0}, *ptr=NULL;

	time_t tm=time(NULL);
	FILE *fp = fopen("/proc/uptime", "r");
	fgets(line, sizeof(line), fp);
	sscanf(line, "%s", uptime);
	ptr = strchr(line, '.');
	*ptr = 0;

	snprintf(xml, sizeof(xml), bfmt, ctime(&tm), line);
	write(client, xml, strlen(xml));
	return 0;
}

int get_system_server(int client, char *ibuf, int len, char *subtok)
{
	if(!strcmp(ibuf, "/traffic")){
		get_sys_traffic(client);
	}

	if(!strcmp(ibuf, "/basic")){
		get_sys_basic(client);
	}
	return 0;
}

int post_system_server(int client, char *ibuf, int len, char *torken)
{
	return 0;
}
