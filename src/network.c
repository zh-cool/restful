#include <stdio.h>
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

#define NETTYPELEN	8
#define USERNAMELEN	32
#define PASSWORDLEN	32

static int get_lan_server(int client)
{
	char *lanfmt =  "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<Network>"
			"<IFNAME>br-lan</IFNAME>"
			"<PROTO>"
				"<TYPE>%s</TYPE>"
				"<IP>%s</IP>"
				"<NETMASK>%s</NETMASK>"
				"<MAC>%s</MAC>"
			"</PROTO>"
		"</Network>";


	char xml[XMLLEN] = {0};
	char type[NETTYPELEN] = {0};
	char ip[INET_ADDRSTRLEN] = {0};
	char netmask[INET_ADDRSTRLEN] = {0};

	struct if_cfg cfg;

	get_interface_cfg("br-lan", &cfg);

	snprintf(type, sizeof(type), "%s", 
			uci_get_cfg("network.lan.proto", xml, sizeof(xml)));

	snprintf(ip, sizeof(ip), "%s", 
			uci_get_cfg("network.lan.ipaddr", xml, sizeof(xml)));

	snprintf(netmask, sizeof(netmask), "%s", 
			uci_get_cfg("network.lan.netmask", xml, sizeof(xml)));

	snprintf(xml, sizeof(xml), lanfmt, type, ip, netmask, cfg.mac);
	write(client, xml, strlen(xml));
	return 0;
}

static int post_lan_server(int client, char *inbuf)
{        
	ezxml_t root = NULL, ip=NULL, netmask=NULL, proto=NULL;
	int length = strlen(inbuf);

        root = ezxml_parse_str(inbuf, length);
	if(!root)
		return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);

        if(root && *ezxml_error(root)) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

	if(NULL == (proto=ezxml_child(root, "PROTO"))){
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, "PROTO NOT FOUND");
	}

        if(NULL == (ip=ezxml_child(proto, "IP"))) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, "IP NOT FOUND");
        }

        if(NULL == (netmask=ezxml_child(proto, "NETMASK"))) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, "NETMASK NOT FOUND");
        }
	
	if((ip->txt[0] && isip(ip->txt)) &&
			(netmask->txt[0] && isnetmask(netmask->txt))){

		uci_set_cfg("network.lan.ipaddr", ip->txt);
		uci_set_cfg("network.lan.netmask", netmask->txt);
		uci_commit_change("network");
		system("/etc/init.d/network restart");
	}else{
		ezxml_free(root);
		return response_state(client, FORMAT_ERR, "Invalid network address");
	}
	
	ezxml_free(root);
	return 0;
}

static int get_wan_server(int client)
{
	char xml[XMLLEN] = {0};
	char type[NETTYPELEN] = {0};
	char ip[INET_ADDRSTRLEN] = {0};
	char netmask[INET_ADDRSTRLEN] = {0};
	char gateway[INET_ADDRSTRLEN] = {0};
	char broadcast[INET_ADDRSTRLEN] = {0};
	char dns[INET_ADDRSTRLEN*16] = {0};
	char ifname[IFNAMSIZ] = {0};
	struct if_cfg cfg;
	
	bzero(&cfg, sizeof(cfg));
	snprintf(type, sizeof(type), "%s", uci_get_cfg("network.wan.proto", xml, sizeof(xml)));
	snprintf(ifname, sizeof(ifname), "%s", uci_get_cfg("network.wan.ifname", xml, sizeof(xml)));
	get_interface_cfg(ifname, &cfg);

	if(!strncmp(type, "dhcp", strlen("dhcp"))){
		char *wanfmt = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
			       "<NETWORK>"
					"<IFNAME>%s</IFNAME>"
			       		"<PROTO>"
						"<TYPE>%s</TYPE>"
						"<IP>%s</IP>"
						"<NETMASK>%s</NETMASK>"
						"<MAC>%s</MAC>"
						"<GATEWAY>%s</GATEWAY>"
						"<BROADCAST>%s</BROADCAST>"
						"%s" //DNS
					"</PROTO>"
			       "</NETWORK>";

		//DNS
		get_wan_dns(xml, sizeof(xml));
		char *ptr = xml, *tok=NULL;
		int pos=0, len=0;
		do{
			tok = strchr(ptr, ' ');
			if(tok){
				*tok++ = 0;
				len = snprintf(dns+pos, sizeof(dns)-pos, "<DNS>%s</DNS>", ptr);
				pos += len;
				ptr = tok;
			}else{
				len = snprintf(dns+pos, sizeof(dns)-pos, "<DNS>%s</DNS>", ptr);
				break;
			}
		}while(*ptr);
		//DNS
                                                                                                 
		snprintf(xml, sizeof(xml), wanfmt, 
				ifname, 
				type, 
				cfg.ip, 
				cfg.netmask, 
				cfg.mac, 
				get_wan_gateway(gateway, sizeof(gateway)), 
				cfg.broadaddr, 
				dns);

		write(client, xml, strlen(xml));
	}else if(!strncmp(type, "static", strlen("static"))){
		char *wanfmt =  "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
				"<Network>"
					"<IFNAME>%s</IFNAME>"
					"<PROTO>"
						"<TYPE>%s</TYPE>"
						"<IP>%s</IP>"
						"<NETMASK>%s</NETMASK>"
						"<MAC>%s</MAC>"
						"<GATEWAY>%s</GATEWAY>"
						"<BROADCAST>%s</BROADCAST>"
						"%s" //DNS
					"</PROTO>"
				"</Network>";
		
		snprintf(ip, sizeof(ip), "%s", uci_get_cfg("network.wan.ipaddr", xml, sizeof(xml)));
		snprintf(netmask, sizeof(netmask), "%s", uci_get_cfg("network.wan.netmask", xml, sizeof(xml)));
		snprintf(gateway, sizeof(gateway), "%s", uci_get_cfg("network.wan.gateway", xml, sizeof(xml)));
		snprintf(broadcast, sizeof(broadcast), "%s", uci_get_cfg("network.wan.broadcast", xml, sizeof(xml)));
		//DNS
		uci_get_cfg("network.wan.dns", xml, sizeof(xml));
		char *ptr = xml, *tok=NULL;
		int pos=0, len=0;
		do{
			tok = strchr(ptr, ' ');
			if(tok){
				*tok++ = 0;
				len = snprintf(dns+pos, sizeof(dns)-pos, "<DNS>%s</DNS>", ptr);
				pos += len;
				ptr = tok;
			}else{
				len = snprintf(dns+pos, sizeof(dns)-pos, "<DNS>%s</DNS>", ptr);
				break;
			}
		}while(*ptr);
		//DNS

		snprintf(xml, sizeof(xml), wanfmt, 
				ifname, 
				type, 
				ip, 
				netmask, 
				cfg.mac, 
				gateway, 
				broadcast, 
				dns);

		write(client, xml, strlen(xml));
	}else if(!strncmp(type, "pppoe", strlen("pppoe"))){
		char username[USERNAMELEN] = {0};
		char password[PASSWORDLEN] = {0};
		char *wanfmt = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
			       "<Network>"
				       	"<IFNAME>%s</IFNAME>"
					"<PROTO>"
						"<TYPE>%s</TYPE>"
						"<USER_NAME>%s</USER_NAME>"
						"<PASSWORD>%s</PASSWORD>"
						"<IP>%s</IP>"
						"<NETMASK>255.255.255.255</NETMASK>"
						"<MAC></MAC>"
						"<GATEWAY>%s</GATEWAY>"
						"<BROADCAST></BROADCAST>"
						"%s"   //DNS
					"</PROTO>"
				"</Network>";

		snprintf(username, sizeof(username), "%s", 
				uci_get_cfg("network.wan.username", xml, sizeof(xml)));

		snprintf(password, sizeof(password), "%s", 
				uci_get_cfg("network.wan.password", xml, sizeof(xml)));

		snprintf(ip, sizeof(ip), "%s", 
				get_wan_ip(xml, sizeof(xml)));

		snprintf(gateway, sizeof(gateway), "%s", 
				get_wan_gateway(xml, sizeof(xml)));

		//DNS
		get_wan_dns(xml, sizeof(xml));
		char *ptr = xml, *tok=NULL;
		int pos=0, len=0;
		do{
			tok = strchr(ptr, ' ');
			if(tok){
				*tok++ = 0;
				len = snprintf(dns+pos, sizeof(dns)-pos, "<DNS>%s</DNS>", ptr);
				pos += len;
				ptr = tok;
			}else{
				len = snprintf(dns+pos, sizeof(dns)-pos, "<DNS>%s</DNS>", ptr);
				break;
			}
		}while(*ptr);
		//DNS

		snprintf(xml, sizeof(xml), wanfmt, 
				ifname, type, 
				username, 
				password, 
				ip, 
				gateway, 
				dns);
		write(client, xml, strlen(xml));
	}
	return 0;
}

int post_wan_server(int client, char *inbuf)
{	
	ezxml_t root = NULL, proto=NULL, type=NULL;
	int length = strlen(inbuf);

        root = ezxml_parse_str(inbuf, length);
	if(!root){
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
	}
        if(root && *ezxml_error(root)) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

        if(NULL == (proto=ezxml_child(root, "PROTO"))) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

        if(NULL == (type=ezxml_child(proto, "TYPE"))) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

	if(!strncmp(type->txt, "static", strlen(type->txt)) && 
			(strlen(type->txt)==strlen("static"))){
		ezxml_t ip = ezxml_child(proto, "IP");
		ezxml_t netmask =  ezxml_child(proto, "NETMASK");
		ezxml_t gateway =  ezxml_child(proto, "GATEWAY");
		ezxml_t broadcast = ezxml_child(proto, "BROADCAST");
		ezxml_t dns = ezxml_child(proto, "DNS");
		char dnsbuf[INET_ADDRSTRLEN*16] = {0};
		int len=0;

		if(!ip || !ip->txt[0] || !isip(ip->txt) || 
				!netmask || !netmask->txt[0] || 
				!isnetmask(netmask->txt)){
			ezxml_free(root);
			return response_state(client, FORMAT_ERR, "Invalid ip addr or netmask addr");
		}

		while(dns){
			if(!dns->txt[0]){
				dns = dns->next;
				continue;
			}

			if(!isip(dns->txt)){
				ezxml_free(root);
				return response_state(client, FORMAT_ERR, "Invalid dns ip address");
			}
			strncat(dnsbuf, dns->txt, sizeof(dnsbuf));
			strncat(dnsbuf, " ", sizeof(dnsbuf));
			dns = dns->next;
		}
		if((len=strlen(dnsbuf)) && (dnsbuf[len-1]==' ')){
			dnsbuf[len-1] = 0;
		}	

		if(gateway && gateway->txt[0]){
			if(!isip(gateway->txt)){
				ezxml_free(root);
				return response_state(client, FORMAT_ERR, "Invalid gateway ip address");
			}
		}

		if(broadcast && broadcast->txt[0]){
			if(!isip(broadcast->txt)){
				ezxml_free(root);
				return response_state(client, FORMAT_ERR, "Invalid broadcast ip address");
			}
		}

		uci_set_cfg("network.wan.proto", type->txt);
		uci_set_cfg("network.wan.ipaddr", ip->txt);
		uci_set_cfg("network.wan.netmask", netmask->txt);
		if(gateway && gateway->txt[0]){ 
			uci_set_cfg("network.wan.gateway", gateway->txt);
		}else{
			uci_set_cfg("network.wan.gateway", "");
		}

		if(broadcast && broadcast->txt[0]){
		       	uci_set_cfg("network.wan.broadcast", broadcast->txt);
		}else{
		       	uci_set_cfg("network.wan.broadcast", "");

		}

		if(dnsbuf[0]){
		       	uci_set_cfg("network.wan.dns", dnsbuf);
		}else{
		       	uci_set_cfg("network.wan.dns", "");
		}

		uci_commit_change("network");
		system("/etc/init.d/network restart");
	}else if(!strncmp(type->txt, "pppoe", strlen(type->txt)) && 
			(strlen(type->txt)==strlen("pppoe"))){
		ezxml_t username = ezxml_child(proto, "USER_NAME");
		ezxml_t password =  ezxml_child(proto, "PASSWORD");
		if(!username || !password){
			ezxml_free(root);
			return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
		}

		uci_set_cfg("network.wan.proto", type->txt);
		uci_set_cfg("network.wan.username", username->txt);
		uci_set_cfg("network.wan.password", password->txt);
		uci_set_cfg("network.wan.netmask", "");
		uci_set_cfg("network.wan.broadcast", "");
		uci_set_cfg("network.wan.ipaddr", "");
		uci_set_cfg("network.wan.gateway", "");
		uci_set_cfg("network.wan.dns", "");
		uci_commit_change("network");
		system("/etc/init.d/network restart");
	}else if(!strncmp(type->txt, "dhcp", strlen(type->txt)) && 
			(strlen(type->txt)==strlen("dhcp"))){
		uci_set_cfg("network.wan.proto", type->txt);

		uci_set_cfg("network.wan.netmask", "");
		uci_set_cfg("network.wan.broadcast", "");
		uci_set_cfg("network.wan.ipaddr", "");
		uci_set_cfg("network.wan.gateway", "");
		uci_set_cfg("network.wan.dns", "");
		uci_commit_change("network");
		system("/etc/init.d/network restart");
	}else{
		ezxml_free(root);
		return response_state(client, NO_SUPPORT_OPERATE, "Invalid proto type");
	}

	ezxml_free(root);
	return 0;
}

int get_network_server(int client, char *ibuf, int len, char *subtok)
{
	char *arg = ibuf;
	int ret = 0;
	if(0==len){
		return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
	}

	if(!strncmp(arg, "/lan", len) && (strlen("/lan")==len) ){
		ret = get_lan_server(client);
	}else if(!strncmp(arg, "/wan", len) && (strlen("/wan")==len)){
		ret = get_wan_server(client);
	}else{
		return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
	}
	return ret;
}

int post_network_server(int client, char *ibuf, int len, char *subtok)
{
	int ret = 0;

	if(subtok >= ibuf){
		return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
	}

	if(!strncmp(subtok, "/lan", ibuf-subtok)){
		ret = post_lan_server(client, ibuf);
	}else if(!strncmp(subtok, "/wan", ibuf-subtok)){
		ret = post_wan_server(client, ibuf);
	}else{
		return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
	}
	
	return ret;
}
