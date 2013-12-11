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
#include <linux/reboot.h>
#include <sys/reboot.h>
#include <dirent.h>
#include <error.h>
#include <ctype.h>
#include <time.h>
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

static int get_sys_backup(int client)
{
	char *bfmt = 	"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
			"<SYSTEM>"
				"<URL>%s</URL>"
			"</SYSTEM>";

	char fname[PATH_MAX]={0}, xml[XMLLEN]={0};
	time_t t = time(NULL);
	struct tm tmm, *tm; 

	tm = gmtime_r(&t, &tmm);

	sprintf(fname, "/cgi-bin/backup-%d%d%d-%d:%d:%d.tar.gz", 
			(tm->tm_year+1900), 
			(tm->tm_mon+1), 
			tm->tm_mday, 
			tm->tm_hour, 
			tm->tm_min, 
			tm->tm_sec
	       );

	snprintf(xml, sizeof(xml), "/usr/bin/find /etc -type f |xargs /bin/tar -czvf /www%s", fname);
	system(xml);

	snprintf(xml, sizeof(xml), bfmt, fname);
	write_to_server(client, xml, strlen(xml));
	return 0;
}

int get_system_server(int client, char *ibuf, int len, char *subtok)
{
	if(!strcmp(ibuf, "/traffic")){
		return get_sys_traffic(client);
	}

	if(!strcmp(ibuf, "/basic")){
		return get_sys_basic(client);
	}

	if(!strcmp(ibuf, "/backup")){
		return get_sys_backup(client);
	}
	return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
}

int post_sys_restore(char *url)
{
	char ifname[PATH_MAX]={0};
	char cmd[XMLLEN] = {0};

	sprintf(ifname, "/www%s", url);
	sprintf(cmd, "/bin/tar -C / -xzvf %s", ifname);
	printf("%s\n%s\n", ifname, cmd);

	system(cmd);
	reboot(LINUX_REBOOT_CMD_RESTART);
	pause();
}

int post_system_server(int client, char *ibuf, int len, char *torken)
{
	if(strncmp(torken, "/active", ibuf-torken)){
		return response_state(client, NO_SERVICE, "Invalid service");
	}

	ezxml_t root = NULL, act=NULL;
	root = ezxml_parse_str(ibuf, len);
	if(!root){
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
	}
        if(root && *ezxml_error(root)) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

	act = ezxml_child(root, "ACT");
	if(act && !strcmp(act->txt, "Reboot")){
		reboot(LINUX_REBOOT_CMD_RESTART);
	}

	if(act && !strcmp(act->txt, "Poweroff")){
		reboot(LINUX_REBOOT_CMD_POWER_OFF);
	}

	if(act && !strcmp(act->txt, "Reset")){
		system("/sbin/mtd -r erase rootfs_data");
	}

	if(act && !strcmp(act->txt, "Restore")){
		ezxml_t url = ezxml_child(root, "URL");
		post_sys_restore(url->txt);
	}

	ezxml_free(root);
	return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
}
