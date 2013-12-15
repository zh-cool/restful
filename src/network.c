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

#define NETTYPELEN      8
#define USERNAMELEN     32
#define PASSWORDLEN     32

static int get_port_status(char *port, int len)
{

        char *pfmt = "<PORT>"
                        "<NUM>%d</NUM>"
                        "<STATUS>%s</STATUS>"
                     "</PORT>";

        FILE *fp = NULL;
        char line[128]={0}, *ptr=NULL, *status=NULL;
        int pos=0, cnt=0;

        fp = popen("/sbin/swconfig dev eth0 show", "r");
        if(!fp){
                return 1;
        }

        while(fgets(line, sizeof(line), fp)){
                ptr = strstr(line, "link: port:");
                if(!ptr) continue;
                ptr += strlen("link: port:");

                status = strstr(ptr, "link:");
                if(!status) continue;
                *status = 0;
                status += strlen("link:");
                cnt = strlen(status);
                if(status[cnt-1] == '\n'){
                        status[cnt-1] = 0;
                }

                cnt = snprintf(port+pos, len-pos, pfmt, atoi(ptr), status);
                pos += cnt;
        }
        return 0;
}

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
                        "<SWITCH>"
                        "%s"
                        "</SWITCH>"
                "</Network>";


        char xml[XMLLEN] = {0};
        char type[NETTYPELEN] = {0};
        char ip[INET_ADDRSTRLEN] = {0};
        char netmask[INET_ADDRSTRLEN] = {0};
        char port[XMLLEN] = {0};

        struct if_cfg cfg;

        get_interface_cfg("br-lan", &cfg);

        snprintf(type, sizeof(type), "%s",
                        uci_get_cfg("network.lan.proto", xml, sizeof(xml)));

        snprintf(ip, sizeof(ip), "%s",
                        uci_get_cfg("network.lan.ipaddr", xml, sizeof(xml)));

        snprintf(netmask, sizeof(netmask), "%s",
                        uci_get_cfg("network.lan.netmask", xml, sizeof(xml)));

        get_port_status(port, sizeof(port));

        snprintf(xml, sizeof(xml), lanfmt, type, ip, netmask, cfg.mac, port);
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
        snprintf(type, sizeof(type), "%s",
                        uci_get_cfg("network.wan.proto", xml, sizeof(xml)));
        snprintf(ifname, sizeof(ifname), "%s",
                        uci_get_cfg("network.wan.ifname", xml, sizeof(xml)));
        get_interface_cfg(ifname, &cfg);

        char *dnsfmt = "<DNS>"
                               "<IP>%s</IP>"
                               "<LEVEL>%s</LEVEL>"
                       "</DNS>";

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
                                len = snprintf(dns+pos, sizeof(dns)-pos, dnsfmt,
                                                ptr,
                                                pos ? "Savle" : "Master");
                                pos += len;
                                ptr = tok;
                        }else{
                                len = snprintf(dns+pos, sizeof(dns)-pos, dnsfmt,
                                                ptr,
                                                pos ? "Savle" : "Master");
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

                uci_get_cfg("network.wan.ipaddr", ip, sizeof(ip));
                uci_get_cfg("network.wan.netmask", netmask, sizeof(netmask));
                uci_get_cfg("network.wan.gateway", gateway, sizeof(gateway));
                uci_get_cfg("network.wan.broadcast", broadcast,
                                sizeof(broadcast));
                //DNS
                uci_get_cfg("network.wan.dns", xml, sizeof(xml));
                char *ptr = xml, *tok=NULL;
                int pos=0, len=0;
                do{
                        tok = strchr(ptr, ' ');
                        if(tok){
                                *tok++ = 0;
                                len = snprintf(dns+pos, sizeof(dns)-pos, dnsfmt,
                                        ptr,
                                        pos ? "Slave" : "Master");
                                pos += len;
                                ptr = tok;
                        }else{
                                len = snprintf(dns+pos, sizeof(dns)-pos, dnsfmt,
                                        ptr,
                                        pos ? "Slave" : "Master");
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

                uci_get_cfg("network.wan.username", username, sizeof(username));
                uci_get_cfg("network.wan.password", password, sizeof(password));
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
                                len = snprintf(dns+pos, sizeof(dns)-pos, dnsfmt,
                                                ptr,
                                                pos ? "Slave" : "Master");
                                pos += len;
                                ptr = tok;
                        }else{
                                len = snprintf(dns+pos, sizeof(dns)-pos, dnsfmt,
                                                ptr,
                                                pos ? "Slave" : "Master");
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
                ezxml_t dnsip = NULL;
                char dnsbuf[INET_ADDRSTRLEN*16] = {0};
                int len=0;

                if(!ip || !ip->txt[0] || !isip(ip->txt) ||
                                !netmask || !netmask->txt[0] ||
                                !isnetmask(netmask->txt)){
                        ezxml_free(root);
                        return response_state(client, FORMAT_ERR, "Invalid ip addr or netmask addr");
                }

                while(dns){
                        dnsip = ezxml_child(dns, "IP");
                        if(!dnsip->txt[0]){
                                dns = dns->next;
                                continue;
                        }

                        if(!isip(dnsip->txt)){
                                ezxml_free(root);
                                return response_state(client, FORMAT_ERR, "Invalid dns ip address");
                        }
                        strncat(dnsbuf, dnsip->txt, sizeof(dnsbuf));
                        strncat(dnsbuf, " ", sizeof(dnsbuf));
                        dns = dnsip->next;
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
                ezxml_t predns = ezxml_child(proto, "PREDNS");
                char dnsbuf[INET_ADDRSTRLEN*16] = {0};
                int len=0;

                if(!username || !password){
                        ezxml_free(root);
                        return response_state(client,
                                        FORMAT_ERR,
                                        err_msg[FORMAT_ERR]
                                        );
                }

                if(predns){
                        ezxml_t enabled = ezxml_child(predns, "ENABLED");
                        ezxml_t dnsip = NULL;
                        if(enabled && enabled->txt[0]=='0'){
                                ezxml_t dns = ezxml_child(predns, "DNS");
                                while(dns){
                                        dnsip = ezxml_child(dns, "IP");
                                        if(!dnsip->txt[0]){
                                                dns = dns->next;
                                                continue;
                                        }

                                        if(!isip(dnsip->txt)){
                                                ezxml_free(root);
                                                return response_state(client,
                                                                FORMAT_ERR,
                                                                "Invalid dns ip address"
                                                                );
                                        }
                                        strncat(dnsbuf, dnsip->txt,
                                                        sizeof(dnsbuf));
                                        strncat(dnsbuf, " ", sizeof(dnsbuf));
                                        dns = dns->next;
                                }
                                if((len=strlen(dnsbuf)) && (dnsbuf[len-1]==' '))
                                        dnsbuf[len-1] = 0;
                        }
                }
                uci_set_cfg("network.wan.peerdns", strlen(dnsbuf) ? "0" : "");
                uci_set_cfg("network.wan.dns", dnsbuf);

                uci_set_cfg("network.wan.proto", type->txt);
                uci_set_cfg("network.wan.username", username->txt);
                uci_set_cfg("network.wan.password", password->txt);
                uci_set_cfg("network.wan.netmask", "");
                uci_set_cfg("network.wan.broadcast", "");
                uci_set_cfg("network.wan.ipaddr", "");
                uci_set_cfg("network.wan.gateway", "");
                uci_commit_change("network");
                system("/etc/init.d/network restart");
        }else if(!strncmp(type->txt, "dhcp", strlen(type->txt)) &&
                        (strlen(type->txt)==strlen("dhcp"))){
                uci_set_cfg("network.wan.proto", type->txt);
                ezxml_t predns = ezxml_child(proto, "PREDNS");
                char dnsbuf[INET_ADDRSTRLEN*16] = {0};
                int len=0;
                if(predns){
                        ezxml_t enabled = ezxml_child(predns, "ENABLED");
                        if(enabled && enabled->txt[0]=='0'){
                                ezxml_t dns = ezxml_child(predns, "DNS");
                                ezxml_t dnsip = NULL;
                                while(dns){
                                        dnsip = ezxml_child(dns, "IP");
                                        if(!dnsip->txt[0]){
                                                dns = dns->next;
                                                continue;
                                        }

                                        if(!isip(dnsip->txt)){
                                                ezxml_free(root);
                                                return response_state(client,
                                                                FORMAT_ERR,
                                                                "Invalid dns ip address"
                                                                );
                                        }
                                        strncat(dnsbuf, dnsip->txt,
                                                        sizeof(dnsbuf)
                                                        );
                                        strncat(dnsbuf, " ", sizeof(dnsbuf));
                                        dns = dns->next;
                                }
                                if((len=strlen(dnsbuf)) && (dnsbuf[len-1]==' '))
                                        dnsbuf[len-1] = 0;
                        }
                }
                uci_set_cfg("network.wan.peerdns", strlen(dnsbuf) ? "0" : "");
                uci_set_cfg("network.wan.dns", dnsbuf);


                uci_set_cfg("network.wan.netmask", "");
                uci_set_cfg("network.wan.broadcast", "");
                uci_set_cfg("network.wan.ipaddr", "");
                uci_set_cfg("network.wan.gateway", "");
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

        if(!subtok){
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
