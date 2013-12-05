#ifndef _SERVICE_H_
#define _SERVICE_H_

#define XMLLEN	1024
int get_directory_server(int client, char *ibuf, int len, char *torken);
int post_directory_server(int client, char *ibuf, int len, char *torken);

int get_network_server(int client, char *ibuf, int len, char *torken);
int post_network_server(int client, char *ibuf, int len, char *torken);

int get_wireless_server(int client, char *ibuf, int len, char *torken);
int post_wireless_server(int client, char *ibuf, int len, char *torken);

int get_software_server(int client, char *ibuf, int len, char *torken);
int post_software_server(int client, char *ibuf, int len, char *torken);

int get_dhcp_server(int client, char *ibuf, int len, char *torken);
int post_dhcp_server(int client, char *ibuf, int len, char *torken);

int get_log_server(int client, char *ibuf, int len, char *torken);

int get_time_server(int client, char *ibuf, int len, char *torken);
int post_time_server(int client, char *ibuf, int len, char *torken);
#endif