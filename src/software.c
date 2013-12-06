/*
 * =====================================================================================
 *
 *       Filename:  software.c
 *
 *    Description:  software manager
 *
 *        Version:  1.0
 *        Created:  12/02/2013 12:00:00 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  austin, 
 *   Organization:  ToMoon
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>
#include <error.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>

#include "service.h"
#include "xmlerror.h"
#include "ezxml.h"

static int get_installed_pkg(int client)
{
	char *pfmt =  	"<PACKAGE>"
				"<NAME>%s</NAME>"
				"<VERSION>%s</VERSION>"
			"</PACKAGE>";

	char cmd[] = "/bin/opkg list-installed";
	char line[XMLLEN] = {0}, *ptr=NULL;
	char xml[XMLLEN*8] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><SOFTWARE>";
	int len=0, pos=0;

	FILE *fp = popen(cmd, "r");
	if(fp == NULL){
		return response_state(client, SYS_ERR, strerror(errno));
	}

	pos = strlen(xml);
	while(fgets(line, sizeof(line), fp)){
		if(NULL == (ptr=strstr(line, " - "))){
			return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
		}

		*ptr = 0;
		ptr += 3;
		len = strlen(ptr);
		if(ptr[len-1] == '\n'){
			ptr[len-1] = 0;
		}

		len = snprintf(xml+pos, sizeof(xml)-pos, pfmt, line, ptr);
		pos += len;
	}
	pclose(fp);

	snprintf(xml+pos, sizeof(xml)-pos, "%s", "</SOFTWARE>"); 

	write(client, xml, strlen(xml));
	return 0;
}

static int get_available_pkg(int client)
{	
	char *pfmt =  	"<PACKAGE>"
				"<NAME>%s</NAME>"
				"<VERSION>%s</VERSION>"
			"</PACKAGE>";

	char *cmd[] = {"/bin/opkg update", "/bin/opkg list"};
	char line[XMLLEN*2] = {0}, *ptr=NULL, *des=NULL;
	char xml[XMLLEN*1024] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><SOFTWARE>";
	int len=0, pos=0, n_write=0;

	system(cmd[0]);

	FILE *fp = popen(cmd[1], "r");
	if(fp == NULL){
		return response_state(client, SYS_ERR, strerror(errno));
	}

	pos = strlen(xml);
	while(fgets(line, sizeof(line), fp)){
		if(NULL == (ptr=strstr(line, " - "))){
			return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
		}

		*ptr = 0;
		ptr += 3;

		des = strstr(ptr, " - ");
		if(des)
			*des = 0;

		len = strlen(ptr);
		if(ptr[len-1] == '\n'){
			ptr[len-1] = 0;
		}

		len = snprintf(xml+pos, sizeof(xml)-pos, pfmt, line, ptr);
		pos += len;
	}
	pclose(fp);

	snprintf(xml+pos, sizeof(xml)-pos, "%s", "</SOFTWARE>"); 

	pos = 0;
	len = strlen(xml);
	n_write = 0;

	struct timeval tv = {0, 0};
	while(len){
		if((pos=write(client, xml+n_write, len))<0){
			if(errno == EAGAIN){
				printf("Write error\n");
				tv.tv_sec=0;
				tv.tv_usec=10*1000;
				select(0, NULL, NULL, NULL, &tv);
				continue;
			}
		}
		len -= pos;
		n_write += pos;
	}
	return 0;


}

static int get_upgradeable_pkg(int client)
{	
	char *pfmt =  	"<PACKAGE>"
				"<NAME>%s</NAME>"
				"<VERSION>%s</VERSION>"
			"</PACKAGE>";

	char cmd[] = "/bin/opkg list-upgradable";
	char line[XMLLEN] = {0}, *ptr=NULL;
	char xml[XMLLEN*8] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><SOFTWARE>";
	int len=0, pos=0;

	FILE *fp = popen(cmd, "r");
	if(fp == NULL){
		return response_state(client, SYS_ERR, strerror(errno));
	}

	pos = strlen(xml);
	while(fgets(line, sizeof(line), fp)){
		if(NULL == (ptr=strstr(line, " - "))){
			return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
		}

		*ptr = 0;
		ptr += 3;
		len = strlen(ptr);
		if(ptr[len-1] == '\n'){
			ptr[len-1] = 0;
		}

		len = snprintf(xml+pos, sizeof(xml)-pos, pfmt, line, ptr);
		pos += len;
	}
	pclose(fp);

	snprintf(xml+pos, sizeof(xml)-pos, "%s", "</SOFTWARE>"); 

	write(client, xml, strlen(xml));
	return 0;

	
}

int get_software_server(int client, char *ibuf, int len, char *torken)
{
	if(ibuf && !strcmp(ibuf, "/installed")){
		return get_installed_pkg(client);	
	}

	if(ibuf && !strcmp(ibuf, "/list")){
		return get_available_pkg(client);
	}

	if(ibuf && !strcmp(ibuf, "/upgradable")){
		return get_upgradeable_pkg(client);
	}
	
	return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
}

int post_software_server(int client, char *ibuf, int len, char *subtok)
{	
	char cmd[256];

	if(subtok){
		return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
	}

	ezxml_t root = NULL, active=NULL, act=NULL, name=NULL;

	root = ezxml_parse_str(ibuf, len);
	if(!root){
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
	}
        if(root && *ezxml_error(root)) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

	active = ezxml_child(root, "ACTIVE");
	if(!active){
		ezxml_free(root);
		return 0;
	}

	for(; active; active=active->next){
		act = ezxml_child(active, "ACT");
		if(!act || !act->txt[0]){
			return response_state(client, FORMAT_ERR, "Need Active");
		}

		if(!strcmp(act->txt, "Address")){
			ezxml_t url=ezxml_child(active, "URL");
			FILE *fp = fopen("/etc/opkg.conf", "w");
			if(NULL == fp){
				return response_state(client, SYS_ERR, strerror(errno));
			}

			fprintf(fp, "src/gz ToMoon %s\ndest root /\n" \
					"dest ram /tmp\nlists_dir ext /var/opkg-lists\n" \
					"option overlay_root /overlay", url->txt);
			fclose(fp);
			ezxml_free(root);
			return 0;
		}
	}

	active = ezxml_child(root, "ACTIVE");
	for(; active; active=active->next){
		act = ezxml_child(active, "ACT");
		if(!act || !act->txt[0]){
			return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
		}
		if(!strcmp(act->txt, "Update")){
			system("/bin/opkg update");
			ezxml_free(root);
			return 0;
		}
	}

	active = ezxml_child(root, "ACTIVE");
	for(; active; active=active->next){
		act = ezxml_child(active, "ACT");
		if(!act || !act->txt[0]){
			return response_state(client, FORMAT_ERR, "No Active");
		}

		if(!strcmp(act->txt, "Install")){
			strcpy(cmd, "/bin/opkg install ");
		}else if(!strcmp(act->txt, "Remove")){
			strcpy(cmd, "/bin/opkg remove ");
		}else{
			return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
		}

		name = ezxml_child(active, "NAME");
		for(; name; name=name->next){
			strcat(cmd, name->txt);
			system(cmd);
		}
	}

	ezxml_free(root);
	return 0;
}

