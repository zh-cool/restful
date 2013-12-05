#ifndef _RESTFUL_H_
#define _RESTFUL_H_

typedef int (*SERVER_FUC)(int client, char* ibuf, int len, char *torken);

struct rest_api{
	char *name;
	SERVER_FUC    s_fuc;
};

#endif
