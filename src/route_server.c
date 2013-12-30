#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include "restful.h"
#include "service.h"
#include "xmlerror.h"

#define MAX(a,b) (a)>(b) ? (a):(b)

struct rest_service {
        char *name;
        SERVER_FUC s_fuc;
};

struct rest_service get_rest_service[] = {
        {"directory",   get_directory_server},
        {"network",     get_network_server},
        {"wireless",    get_wireless_server},
        {"software",    get_software_server},
        {"dhcp",        get_dhcp_server},
        {"log",         get_log_server},
        {"time",        get_time_server},
        {"system",      get_system_server},
        {"upnp",        get_upnp_server},
        {"wclient",     get_wclient_server},
        {"parentctr", get_parent_ctr_server},
        {NULL,          NULL}
};

struct rest_service post_rest_service[] = {
        {"directory",   post_directory_server},
        {"network",     post_network_server},
        {"wireless",    post_wireless_server},
        {"software",    post_software_server},
        {"dhcp",        post_dhcp_server},
        {"time",        post_time_server},
        {"system",      post_system_server},
        {"upnp",        post_upnp_server},
        {"wclient",     post_wclient_server},
        {"download",    post_download_server},
        {"login",       post_login_server},
        {"passwd",      post_passwd_server},
        {"parentctr", post_parent_ctr_server},
        {NULL,          NULL}
};

void gateway_server(int client, char *ibuf, int len);

int response_get_service(int client, char *torken, char *arg)
{
        int i=0, ret=1, len=0, torken_len=0;

        if(arg){
                torken_len = arg-torken;
        }else{
                torken_len = strlen(torken);
        }

        while(get_rest_service[i].name){
                len = strlen(get_rest_service[i].name);
                if(!strncmp(get_rest_service[i].name, torken, len) &&
                                (len == torken_len)){
                        ret = get_rest_service[i].s_fuc ?
                              get_rest_service[i].s_fuc(client, arg, arg ?
                                              strlen(arg) : 0, NULL) :
                              response_state(client, NO_SERVICE,
                                              err_msg[NO_SERVICE]);
                        return ret;
                }
                i++;
        }
        return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
}

int response_post_service(int client, char *torken, char *arg)
{
        int i=0, ret=1, torken_len=0, len=0;
        char *ptr=NULL;

        ptr = strchr(torken, '/');
        if(ptr < arg){
                torken_len = ptr-torken;
        }else{
                torken_len = arg-torken;
                ptr = NULL;
        }

        while(post_rest_service[i].name){
                len = strlen(post_rest_service[i].name);
                if(!strncmp(post_rest_service[i].name, torken, len) &&
                                (torken_len==len)){
                        ret = post_rest_service[i].s_fuc ?
                              post_rest_service[i].s_fuc(client, arg,
                                              strlen(arg), ptr) :
                              response_state(client, NO_SERVICE,
                                              err_msg[NO_SERVICE]
                                              );

                        return ret ? ret :
                                response_state(client, ret, err_msg[ret]);
                }
                i++;
        }
        response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
        return NO_SERVICE;
}

void route_server(int client, char *ibuf, int len)
{
        char *pos=NULL, *torken=NULL, *arg=NULL;

        ibuf[len] = 0;
        fprintf(stderr, "%s", ibuf);
        if(strstr(ibuf, "GET")){
                if((pos=strstr(ibuf, "route"))){
                        torken = strchr(pos, '/');
                        torken++;
                        arg = strchr(torken, '/');
                        response_get_service(client, torken, arg);
                }else{
                }
        }else if(strstr(ibuf, "POST")){
                if((pos=strstr(ibuf, "route"))){
                        torken = strchr(pos, '/');
                        torken++;
                        if((arg=strchr(torken, '\n'))){
                                response_post_service(client, torken, arg);
                        }else{
                                response_state(client, FORMAT_ERR,
                                                err_msg[FORMAT_ERR]
                                                );
                        }
                }
        }else{
                response_state(client, NO_SUPPORT_METHOD,
                                err_msg[NO_SUPPORT_METHOD]
                                );
        }
}


