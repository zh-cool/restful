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

#define IPT_CMD_LEN   10 * 1024
#define URL_CMD_LEN   5 * 1024
#define LINE_LEN      1024

static int config_ipt_rule(int client, ezxml_t root);
static int check_person_list(ezxml_t person_list);


int get_parent_ctr_server(int client, char *ibuf, int len, char *subtok)
{
    char xml[XMLLEN] = {0};
    int i = 0;
    char c = 0;

    FILE *fp = fopen("/etc/parent_ctr.conf", "r");
    while ( (c = fgetc(fp) ) != EOF) {
        xml[i] = c;
        i++;
    }
    fclose(fp);

    write(client, xml, strlen(xml));
    return 0;
}


int post_parent_ctr_server(int client, char *ibuf, int len, char *subtok)
{
    int i = 0;
    char *pTmp = ibuf;
    ezxml_t root = NULL, enabled = NULL;
    
    if (subtok) {
        return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
    }

    FILE *fp = fopen("/etc/parent_ctr.conf", "w");
    if (NULL == fp) {
        return response_state(client, SYS_ERR, strerror(errno));
    }

    for (i = 0; i < len; i++) {
        fputc(*pTmp, fp);
        pTmp++;
    }
    fclose(fp);

    root = ezxml_parse_str(ibuf, len);
    if (!root) {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
    }
    
    if (root && *ezxml_error(root)) {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
    }

    enabled = ezxml_child(root, "ENABLED");
    if (enabled) {
        if (!enabled->txt[0]) {
            ezxml_free(root);
            return response_state(client, FORMAT_ERR, "Invalid ENABLE arg");
        }

        int ienabled = atoi(enabled->txt);
        if ( (ienabled != 0) && (ienabled != 1) ) {
            ezxml_free(root);
            return response_state(client, FORMAT_ERR, "ENABLE arg 0/1");
        }

        if (ienabled) {
            return config_ipt_rule(client, root);
        } else {
            system("echo > /etc/firewall.user");
            system("/etc/init.d/firewall restart");
        }
    } else {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Not found ENABLE arg");
    }

    return 0;
}


static int check_person_list(ezxml_t person_list)
{
    ezxml_t name = NULL, mac = NULL;
    for (; person_list; person_list = person_list->next) {
        name = ezxml_child(person_list, "NAME");
        mac = ezxml_child(person_list, "MAC");
    }

    if (!name || !name->txt[0] || !mac || !mac->txt) {
        return 1;
    }

    return 0;
}


static int config_ipt_rule(int client, ezxml_t root)
{
    ezxml_t parent_list = NULL, parent = NULL, child_list = NULL, child = NULL, child_list_head = NULL;
    ezxml_t begin_time = NULL, end_time = NULL, weekdays = NULL, white_list_enable = NULL;
    ezxml_t white_list = NULL, url = NULL, url_head = NULL, parent_mac = NULL, child_mac = NULL;
    char ipt_cmd[IPT_CMD_LEN] = {0}, url_cmd[URL_CMD_LEN] = {0}, line[LINE_LEN] = {0};
    int is_whole_day = 0, is_every_day = 0, is_white_list_enable = 0;

    /* 检查家长列表 */
    parent_list = ezxml_child(root, "PARENT_LIST");
    if (!parent_list) {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Not found PARENT_LIST arg");
    }
    
    parent = ezxml_child(parent_list, "PARENT");
    if (check_person_list(parent)) {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Parent List");
    }

    /* 生成家长配置规则 */
    for (; parent; parent = parent->next) {
        parent_mac = ezxml_child(parent, "MAC");
        if (0 == parent_mac->txt[0]) {
            continue;
        }
        snprintf(line, sizeof(line), 
            "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 -j ACCEPT\n", 
            parent_mac->txt);
        strcat(ipt_cmd, line);
    }

    /* 获取规则开始时间，如果为空视为全天 */
    begin_time = ezxml_child(root, "BEGIN_TIME");
    if (begin_time) {
        if (begin_time->txt[0]) {
            is_whole_day = 0;
        } else {
            is_whole_day = 1;
        }
    } else {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Not found BEGIN_TIME arg");
    }

    /* 获取规则结束时间 */
    end_time = ezxml_child(root, "END_TIME");
    if (end_time) {
        if ( (1 == is_whole_day) && (end_time->txt[0]) ) {
            ezxml_free(root);
            return response_state(client, FORMAT_ERR, "END_TIME should be empty");
        }
    } else {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Not found END_TIME arg");
    }

    /* 获取规则生效的weekdays */
    weekdays = ezxml_child(root, "WEEKDAYS");
    if (weekdays) {
        if (weekdays->txt[0]) {
            is_every_day = 0;
        } else {
            is_every_day = 1;
        }
    } else {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Not found WEEKDAYS arg");
    }

    /* 获取url白名单，如未开启则认为孩子可访问任意网站 */
    white_list_enable = ezxml_child(root, "WHITE_LIST_ENABLE");
    if (white_list_enable) {
        if (!strcmp("0", white_list_enable->txt)) {
            is_white_list_enable = 0;
        } else if (!strcmp("1", white_list_enable->txt)) {
            is_white_list_enable = 1;
            /* 获取url list */
            white_list = ezxml_child(root, "WHITE_LIST");
            if (white_list) {
                url = ezxml_child(white_list, "URL");
                if (url) {
                    url_head = url;
                } else {
                    ezxml_free(root);
                    return response_state(client, FORMAT_ERR, "Not found URL arg");
                }
            } else {
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, "Not found WHITE_LIST arg");
            }
        } else {
            ezxml_free(root);
            return response_state(client, FORMAT_ERR, "Invalid WHITE_LIST_ENABLE arg");
        }
    } else {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Not found WHITE_LIST_ENABLE arg");
    }

    /* 检查孩子列表 */
    child_list = ezxml_child(root, "CHILD_LIST");
    if (!child_list) {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Not found CHILD_LIST arg");
    }

    child = ezxml_child(child_list, "CHILD");
    if (check_person_list(child)) {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Child List");
    }
    child_list_head = child;

    /* 生成孩子配置规则 */
    for (; child; child = child->next) {
        child_mac = ezxml_child(child, "MAC");
        if (0 == child_mac->txt[0]) {
            continue;
        }
        if (is_every_day && is_whole_day) {
            if (1 == is_white_list_enable) {
                for (url = url_head; url; url = url->next) {
                    if (0 != url->txt[0]) {
                        snprintf(line, sizeof(line), 
                            "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 "
                            "-m string --string %s --algo bm -j ACCEPT\n", 
                            child_mac->txt, url->txt);
                        strcat(url_cmd, line);
                    }
                }
            } else {
                snprintf(line, sizeof(line), 
                    "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 -j ACCEPT\n", 
                    child_mac->txt);
            }
        } else if (is_every_day && !is_whole_day) {
            if (1 == is_white_list_enable) {
                for (url = url_head; url; url = url->next) {
                    if (0 != url->txt[0]) {
                        snprintf(line, sizeof(line), 
                            "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 "
                            "-m time --timestart %s --timestop %s -m string --string %s --algo bm -j ACCEPT\n",
                            child_mac->txt, begin_time->txt, end_time->txt, url->txt);
                        strcat(url_cmd, line);
                    }
                }
            } else {
                snprintf(line, sizeof(line), 
                    "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 "
                    "-m time --timestart %s --timestop %s -j ACCEPT\n",
                    child_mac->txt, begin_time->txt, end_time->txt);
            }
        } else if (!is_every_day && is_whole_day) {
            if (1 == is_white_list_enable) {
                for (url = url_head; url; url = url->next) {
                    if (0 != url->txt[0]) {
                        snprintf(line, sizeof(line), 
                            "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 "
                            "-m time --weekdays %s -m string --string %s --algo bm -j ACCEPT\n",
                            child_mac->txt, weekdays->txt, url->txt);
                        strcat(url_cmd, line);
                    }
                }
            } else {
                snprintf(line, sizeof(line), 
                    "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 "
                    "-m time --weekdays %s -j ACCEPT\n",
                    child_mac->txt, weekdays->txt);
            }
        } else if (!is_every_day && !is_whole_day) {
            if (1 == is_white_list_enable) {
                for (url = url_head; url; url = url->next) {
                    if (0 != url->txt[0]) {
                        snprintf(line, sizeof(line), 
                            "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 "
                            "-m time --timestart %s --timestop %s --weekdays %s -m string --string %s --algo bm -j ACCEPT\n",
                            child_mac->txt, begin_time->txt, end_time->txt, weekdays->txt, url->txt);
                        strcat(url_cmd, line);
                    }
                }
            } else {
                snprintf(line, sizeof(line), 
                    "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 "
                    "-m time --timestart %s --timestop %s --weekdays %s -j ACCEPT\n",
                    child_mac->txt, begin_time->txt, end_time->txt, weekdays->txt);
            }
        } else {
            /* do nothing */
        }

        if (1 == is_white_list_enable) {
            strcat(ipt_cmd, url_cmd);
            memset(url_cmd, 0, URL_CMD_LEN);
        } else {
            strcat(ipt_cmd, line);
        }
    }
    
    ezxml_t others_enabled = ezxml_child(root, "OTHERS_ENABLED");
    if (!others_enabled) {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Not found OTHERS_ENABLED arg");
    }

    if (!strcmp("0", others_enabled->txt)) {
        strcat(ipt_cmd, "iptables -A input_rule -p udp --dport 53 -j DROP\n");
    } else if (!strcmp("1", others_enabled->txt)) {
        for (child = child_list_head; child; child = child->next) {
            child_mac = ezxml_child(child, "MAC");
            if (0 == child_mac->txt[0]) {
                continue;
            }
            snprintf(line, sizeof(line), 
                "iptables -A input_rule -m mac --mac-source %s -p udp --dport 53 -j DROP\n",
                child_mac->txt);
            strcat(ipt_cmd, line);
        }
        strcat(ipt_cmd, "iptables -A input_rule -p udp --dport 53 -j ACCEPT\n");
    } else {
        ezxml_free(root);
        return response_state(client, FORMAT_ERR, "Invalid OTHERS_ENABLED arg");
    }


    FILE *fp = fopen("/etc/firewall.user", "w");
    if (NULL == fp) {
        return response_state(client, SYS_ERR, strerror(errno));
    }

    int i = 0;
    for (i = 0; i < strlen(ipt_cmd); i++) {
        fputc(ipt_cmd[i], fp);
    }
    fclose(fp);

    return 0;
}
