/*
POST /app/route/directory
<?xml version="1.0" encoding="utf-8"?>
<DIRECTORY>
    <ACTION>Create</ACTION>
    <DIR>name1</DIR>
    <DIR>name2</DIR>
</DIRECTORY>
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <error.h>
#include "restful.h"
#include "service.h"
#include "ezxml.h"
#include "xmlerror.h"
#include "errno.h"

extern char* urldecode(const char *in_str, char *out_str, int len);
static char *xmlhead = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                       "<DIRECTORY>";

#define SYS_MOUNT_ROOT	"/media"
#define MAX_BUF 1024*1024
#define ERRFMT "<?xml version=\"1.0\" encoding=\"utf-8\"?><ERROR><CODE>%d</CODE><MESSAGE>%s</MESSAGE></ERROR>"

static int remove_file(const char *path)
{
        struct stat stat;
        DIR *dir = NULL;
        struct dirent *it = NULL;
        char npath[PATH_MAX];
        int ret;

        if(lstat(path, &stat) < 0) {
                return errno;
        }

        if(S_ISREG(stat.st_mode)) {
                if(unlink(path) < 0) {
                        return errno;
                }
        }

        if(S_ISDIR(stat.st_mode)) {
                if(NULL == (dir=opendir(path))) {
                        return errno;
                }

                while((it=readdir(dir))) {
                        if(!strcmp(it->d_name, ".") || !strcmp(it->d_name, "..")) {
                                continue;
                        }
                        snprintf(npath, sizeof(npath), "%s/%s", path, it->d_name);
                        if((ret=remove_file(npath))) {
                                closedir(dir);
                                return ret;
                                break;
                        }
                }
                closedir(dir);

                if(rmdir(path) < 0) {
                        return errno;
                }
        }

        return 0;
}

int post_directory_server(int client, char *ibuf, int length, char *subtork)
{
        ezxml_t root = NULL, action=NULL, dir=NULL, file=NULL;
        char path[PATH_MAX]= {0}, url[PATH_MAX] = {0};

        root = ezxml_parse_str(ibuf, length);
        if(root && *ezxml_error(root)) {
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

        if(NULL == (action=ezxml_child(root, "ACTION"))) {
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

        if(!strcmp(action->txt, "Create")) {
                dir = ezxml_child(root, "DIR");
                file = ezxml_child(root, "FILE");

                for(; dir; dir=dir->next) {
                        strcpy(path, SYS_MOUNT_ROOT);
                        strcat(path, urldecode(dir->txt, url, sizeof(url)));
                        if(mkdir(path, 0775) < 0) {
                                return response_state(client, errno, strerror(errno));
                        }
                }

                for(; file; file=file->next) {
                        int fd;
                        strcpy(path, SYS_MOUNT_ROOT);
                        strcat(path, urldecode(file->txt, url, sizeof(url)));
                        if((fd=open(path, O_RDWR|O_CREAT, 0664)) < 0) {
                                fprintf(stderr, "Can not create %s\n", path);
                                return response_state(client, errno, strerror(errno));
                        } else {
                                close(fd);
                        }
                }
        } else if(!strcmp(action->txt,"Delete")) {
		int ret=0;
                ezxml_t delname = ezxml_child(root, "DEL_NAME");

                if(!delname) {
                        return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
                }
                for(; delname; delname=delname->next) {
                        snprintf(path, sizeof(path), "%s%s", SYS_MOUNT_ROOT, urldecode(delname->txt, url, sizeof(url)));
			if((ret=remove_file(path))){
				return response_state(client, ret, strerror(ret));
			}
                }
        } else if(!strcmp(action->txt,"Rename")) {
                ezxml_t oldname = ezxml_child(root, "OLD_NAME");
                ezxml_t newname = ezxml_child(root, "NEW_NAME");
                char newpath[PATH_MAX];

                if(!oldname || !newname) {
                        return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
                }

                snprintf(path, sizeof(path), "%s%s", SYS_MOUNT_ROOT, urldecode(oldname->txt, url, sizeof(url)));
                snprintf(newpath, sizeof(path), "%s%s", SYS_MOUNT_ROOT, urldecode(newname->txt, url, sizeof(url)));
                if(rename(path, newpath) < 0) {
                        return response_state(client, errno, strerror(errno));
                }
        } else {
                return response_state(client, NO_SUPPORT_OPERATE, err_msg[NO_SUPPORT_OPERATE]);
        }

        return 0;
}

int get_directory_server(int client, char *ibuf, int length, char *torken)
{
        char path[PATH_MAX];
        DIR *dir = NULL;
        struct dirent *it = NULL;
        char xml[MAX_BUF] = {0};
        int len=0, pos=0;

        if(length > PATH_MAX) {
                response_state(client, 1, "Direcotry path tool long");
                return 1;
        }

        strcpy(path, SYS_MOUNT_ROOT);
        if(ibuf) {
                urldecode(ibuf, xml, MAX_BUF);
                strcat(path, xml);
        }

        if(NULL == (dir=opendir(path))) {
                return response_state(client, errno, strerror(errno));
        }

        pos += snprintf(xml+pos, sizeof(xml), "%s", xmlhead);
        while((it=readdir(dir))) {
                if(DT_DIR == it->d_type) {
                        if(!strcmp(".", it->d_name) || !strcmp("..", it->d_name)) {
                                continue;
                        }
                        len = snprintf(xml+pos, sizeof(xml), "<DIR>%s</DIR>", it->d_name);
                } else if(DT_REG == it->d_type) {
                        len = snprintf(xml+pos, sizeof(xml), "<FILE>%s</FILE>", it->d_name);
                } else {
                        continue;
                }
                pos += len;
        }
        len = snprintf(xml+pos, sizeof(xml)-pos, "%s", "</DIRECTORY>");
        closedir(dir);
        write(client, xml, strlen(xml));
        return 0;
}

