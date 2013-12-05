#ifndef _XMLERROR_H_
#define _XMLERROR_H_

#define SERVICE_SUCCESS		0

#define NO_SERVICE		1
#define NO_SUPPORT_METHOD 	2
#define FORMAT_ERR		3
#define NO_SUPPORT_OPERATE 	4
#define SYS_ERR			5

extern char *err_msg[];
int response_state(int client, int code, char *msg);

#endif
