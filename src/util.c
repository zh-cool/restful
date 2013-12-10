#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "util.h"

int cov2xml(char *dst, const char *src, int len)
{
	char *ptr = dst;
	int n = 0, sum = 0;

	while(len--){
		switch(*src){
			case '<':
				n=sprintf(ptr, "%s", "&lt;");
				break;
			case '>':
				n=sprintf(ptr, "%s", "&gt;");
				break;
			case '&':
				n=sprintf(ptr, "%s", "&apos;");
				break;
			case '\'':
				n=sprintf(ptr, "%s", "&apos;");
				break;
			case '"':
				n=sprintf(ptr, "%s", "&quot;");
				break;
			default:
				n = 1;
				*ptr = *src;
		}
		ptr += n;
		src++;
		sum += n;
	}
	return sum;
}

char* get_wan_ip(char *ip, int len)
{
	FILE *fp = popen(". /lib/functions/network.sh; network_get_ipaddr ip wan; echo $ip", "r");
	fgets(ip, len, fp);
	pclose(fp);

	len = strlen(ip);
	if(ip[len-1]=='\n'){
		ip[len-1] = 0;
	}
	return ip;	
}

char* get_wan_gateway(char *gateway, int len)
{
	FILE *fp = popen(". /lib/functions/network.sh; network_get_gateway ip wan; echo $ip", "r");
	fgets(gateway, len, fp);
	pclose(fp);
	
	len = strlen(gateway);
	if(gateway[len-1] == '\n'){
		gateway[len-1] = 0;
	}
	return gateway;	
}

char* get_wan_dns(char *dns, int len)
{
	FILE *fp = popen(". /lib/functions/network.sh; network_get_dnsserver ip wan; echo $ip", "r");
	fgets(dns, len, fp);
	pclose(fp);

	len = strlen(dns);
	if(dns[len-1] == '\n'){
		dns[len-1] = 0;
	}
	return dns;
}

int isip(const char *ip)
{
	struct in_addr in;
	return inet_pton(AF_INET, ip, &in);
}

int isnetmask(const char *netmask)
{
	struct in_addr in;
	if(!inet_pton(AF_INET, netmask, &in)){
		return 0;
	}

	uint32_t mask = in.s_addr;
	mask = ntohl(mask);
	return ((mask|(mask-1))==0xFFFFFFFF);
}

int uci_set_cfg(const char *csp, const char *value)
{
	int len = 0;
	char *cfg = 0;
	len = strlen(csp)+strlen(value)+16;

       	cfg = malloc(len);
	len = snprintf(cfg, len, "uci set %s='%s'", csp, value);
	system(cfg);
	
	free(cfg);
	return 0;
}

int uci_commit_change(const char *config)
{
	char cmd[128] = {0};
	snprintf(cmd, sizeof(cmd), "uci commit %s", config);
	system(cmd);
	return 0;
}

char* uci_get_cfg(const char *cfg, char *buf, int len)
{
	FILE *fp = NULL;
	char cmd[512];

	buf[0] = 0;
	snprintf(cmd, sizeof(cmd), "uci get %s", cfg);
	fp = popen(cmd, "r");
	printf("uci get %s\n", cfg);
	if(NULL == fp){
		return buf;
	}

	fgets(buf, len, fp);

	if(pclose(fp) < 0){
		return buf;
	}

	len = strlen(buf);
	if(len && isspace(buf[len-1])){
		buf[len-1] = 0;
	}

	return buf;
}

int get_interface_cfg(const char *ifname, struct if_cfg *cfg)
{
	struct ifreq ifr;
	struct sockaddr_in* ipaddr = NULL;
	int fd = 0, len=0;

	if((fd=socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		return errno;
	}

	strcpy(ifr.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0){
		return errno;
	}
	len=snprintf(cfg->mac, sizeof(cfg->mac), 
			"%02X:%02X:%02X:%02X:%02X:%02X", 
			(uint8_t)ifr.ifr_hwaddr.sa_data[0],
			(uint8_t)ifr.ifr_hwaddr.sa_data[1],
			(uint8_t)ifr.ifr_hwaddr.sa_data[2],
			(uint8_t)ifr.ifr_hwaddr.sa_data[3],
			(uint8_t)ifr.ifr_hwaddr.sa_data[4],
			(uint8_t)ifr.ifr_hwaddr.sa_data[5]
		);
	cfg->mac[len] = 0;

	if(ioctl(fd,SIOCGIFADDR,&ifr) < 0) {
		return errno;
	}
	ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
	inet_ntop(AF_INET, &ipaddr->sin_addr, cfg->ip, sizeof(struct sockaddr_in));

	if(ioctl(fd, SIOCGIFNETMASK, &ifr) < 0){
		return errno;
	}
	ipaddr = (struct sockaddr_in*)&ifr.ifr_netmask;
	inet_ntop(AF_INET, &ipaddr->sin_addr, cfg->netmask, sizeof(struct sockaddr_in));

	if(ioctl(fd, SIOCGIFBRDADDR, &ifr) < 0){
		return errno;
	}
	ipaddr = (struct sockaddr_in*)&ifr.ifr_broadaddr;
	inet_ntop(AF_INET, &ipaddr->sin_addr, cfg->broadaddr, sizeof(struct sockaddr_in));

	close(fd);
	return 0;	
}

struct arp_tbl* get_arp_tbl(void)
{
	FILE *fp = NULL;
	char line[128];
	struct arp_tbl tbl, *ptbl=&tbl, *ptr=NULL;
	
	fp = fopen("/proc/net/arp", "r");
	fgets(line, sizeof(line), fp);

	while(fgets(line, sizeof(line), fp)){
		ptr = malloc(sizeof(struct arp_tbl));
		ptr->next = NULL;
		ptbl->next = ptr;
		ptbl = ptr;
		sscanf(line, "%s 0x%x 0x%x %s %s %s\n", ptbl->ip, &ptbl->type, &ptbl->flags, ptbl->hwa, ptbl->mask, ptbl->dev);
	}
	fclose(fp);

	if(ptbl == &tbl){
		return NULL;
	}
	return tbl.next;
}

void free_arp_tbl(struct arp_tbl *tbl)
{
	struct arp_tbl *ptr = NULL;

	while(tbl->next){
		ptr = tbl;
		tbl = tbl->next;
		free(ptr);
	}
	free(tbl);
}

char* find_ip_tbl(struct arp_tbl* tbl, char *max)
{
	while(tbl){
		if(!strcasecmp(tbl->hwa, max)){
			return tbl->ip;	
		}
		tbl = tbl->next;
	}
	return NULL;
}

int write_to_server(int client, char *xml, int len)
{
	int pos=0, n_write=0;
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
	return n_write;
}

