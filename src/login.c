#include <stdlib.h>
#include <crypt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <error.h>
#include <ctype.h>
#include <time.h>
#include <shadow.h>
#include "restful.h"
#include "service.h"
#include "ezxml.h"
#include "xmlerror.h"
#include "errno.h"
#include "util.h"

int post_login_server(int client, char *ibuf, int len, char *torken)
{
        if(torken){
                return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
        }

        ezxml_t root = NULL, name=NULL, passwd=NULL;

        root = ezxml_parse_str(ibuf, len);
        if(!root){
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }
        if(root && *ezxml_error(root)) {
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

        name = ezxml_child(root, "USER_NAME");
        passwd = ezxml_child(root, "PASSWD");

        if(!name || !name->txt[0] || !passwd || !passwd->txt[0]){
                return response_state(client, FORMAT_ERR,
                                "Need name and passwd");
        }

        char salt[128] = {0}, *ptr = 0;
        struct spwd *pw = getspnam(name->txt);
        if(!pw){
                return response_state(client, SYS_ERR,
                                "Invalid name");
        }

        ptr = strchr(pw->sp_pwdp+1, '$');
        if(!ptr){
                return response_state(client, SYS_ERR,
                                "Unkonw passwd format");
        }
        ptr = strchr(ptr+1, '$');
        if(!ptr){
                return response_state(client, SYS_ERR,
                                "Unkonw passwd format");
        }
        strncpy(salt, pw->sp_pwdp, ptr-pw->sp_pwdp);

        ptr = crypt(passwd->txt, salt);
        if(!strcmp(ptr, pw->sp_pwdp)){
                return 0;
        }

        return response_state(client, SYS_ERR, "Invalid passwd");
}

