#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <error.h>
#include <ctype.h>
#include "restful.h"
#include "service.h"
#include "ezxml.h"
#include "xmlerror.h"
#include "errno.h"
#include "util.h"
#include "base64.h"

static int download_task(int client, ezxml_t param)
{
        char *dfmt = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                     "<DOWNLOAD>"
                             "<RESP>%s</RESP>"
                     "</DOWNLOAD>";

        char *pdata=0, *resp=0;
        char xml[XMLLEN*4] = {0}, obuf[XMLLEN*4]={0};
        size_t len = 0;
        int ret=0;

        Base64Decode(param->txt, (uint8_t**)&pdata, &len);
        ret = post_request("http://127.0.0.1:6800/jsonrpc",
                        (const char*)pdata,
                        obuf
                        );

        if(ret != 0){
                return response_state(client, SYS_ERR, strerror(errno));
        }
        free(pdata);

        Base64Encode((uint8_t*)obuf, strlen(obuf), &resp);
        snprintf(xml, sizeof(xml), dfmt, resp);

        write_to_server(client, xml, strlen(xml));
        return 1;
}

static int download_config(int client, ezxml_t param)
{
        ezxml_t enable=NULL, dlimit=NULL, ulimit=NULL, cur=NULL, dir=NULL,
                arg=NULL;

        enable= ezxml_child(param, "ENABLED");
        dlimit= ezxml_child(param, "DOWN_LIMIT");
        ulimit= ezxml_child(param, "UP_LIMIT");
        cur   = ezxml_child(param, "CONCURRENT");
        dir   = ezxml_child(param, "DIR");
        arg   = ezxml_child(param, "ARG");

        if(enable && enable->txt[0]){
                uci_set_cfg("uci.aria2.main.enabled", enable->txt);
        }

        if(dlimit && dlimit->txt[0]){
                uci_set_cfg("uci.aria2.main.max_overall_download_limit",
                                dlimit->txt
                           );
        }

        if(ulimit && ulimit->txt){
                uci_set_cfg("uci.aria2.main.max_overall_upload_limit",
                                ulimit->txt
                           );
        }

        if(cur && cur->txt[0]){
                uci_set_cfg("uci.aria2.main.max_concurrent_downloads",
                                cur->txt
                           );
        }

        if(dir && dir->txt[0]){
                uci_set_cfg("uci.aria2.main.default_save_dir", dir->txt);
        }

        system("/sbin/uci commit uci.aria2.main");
        download_task(client, arg);
        return 1;
}

int post_download_server(int client, char *ibuf, int len, char *torken)
{
        if(torken){
                return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
        }

        ezxml_t root = NULL, op=NULL, param=NULL;
        int ret = 0;

        root = ezxml_parse_str(ibuf, len);
        if(!root){
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }
        if(root && *ezxml_error(root)) {
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

        op = ezxml_child(root, "OPERATION");
        param = ezxml_child(root, "PARAM");

        if(!op || !param){
                ezxml_free(root);
                return response_state(client, FORMAT_ERR,
                                "need OPERATION PARAM node");
        }

        if(!strcmp(op->txt, "TASK")){
                ret = download_task(client, param);
        }else if(!strcmp(op->txt, "CONFIG")){
                ret = download_config(client, param);
        }else{
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, "Unkonw OPERATION");
        }

        ezxml_free(root);
        return ret;
}

