#include "xmlerror.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

char *err_msg[]={
	"OK",
	"NO SERVICE",
	"NOT SUPPORT SERVICE",
	"FORMAT ERROR",
	"NOT SUPPORT OPERATE",
	0
};

int response_state(int client, int code, char *msg)
{
	char buf[512] = {0};
	static char *xmlfmt = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		              "<RESULT>"
			      	"<CODE>%d</CODE>"
			      	"<MESSAGE>%s</MESSAGE>"
			      "</RESULT>";
	snprintf(buf, sizeof(buf), xmlfmt, code, msg);
	write(client, buf, strlen(buf));
	return code;
}

