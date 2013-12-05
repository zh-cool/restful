#include <string.h>
#include <ctype.h>

static int php_htoi(char *s)
{
	int value;
	int c;

	c = ((unsigned char *)s)[0];
	if (isupper(c))
		c = tolower(c);
	value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

	c = ((unsigned char *)s)[1];
	if (isupper(c))
		c = tolower(c);
	value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

	return (value);
}

char* urldecode(const char *in_str, char *out_str, int len)
{
	int in_str_len = strlen(in_str);
	char *str;

	str = strdup(in_str);
	char *dest = str;
	char *data = str;

	while (in_str_len--) {
		if (*data == '+') {
			*dest = ' ';
		}
		else if (*data == '%' && in_str_len >= 2 && isxdigit((int) *(data + 1)) 
			&& isxdigit((int) *(data + 2))) {
				*dest = (char) php_htoi(data + 1);
				data += 2;
				in_str_len -= 2;
		} else {
			*dest = *data;
		}
		data++;
		dest++;
	}
	*dest = '\0';

	if(strlen(str) < len){
		strcpy(out_str, str);
	}else{
		return 0;
	}
	return out_str;
}

