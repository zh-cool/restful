#ifndef _UTIL_H_
#define _UTIL_H_

int cov2xml(char *dst, const char *src, int len);
char* get_wan_ip(char *ip, int len);
char* get_wan_dns(char *dns, int len);
char* get_wan_gateway(char *gateway, int len);
int isip(const char *ip);
int isnetmask(const char *netmask);
char* uci_get_cfg(const char *cfg, char *buf, int len);
int uci_set_cfg(const char *csp, const char *value);
int uci_commit_change();
int write_to_server(int client, char *xml, int len);

struct if_cfg{
	char	mac[32];
	char    ip[32];
	char    netmask[32];
	char    broadaddr[32];
};
int get_interface_cfg(const char *ifname, struct if_cfg *cfg);

struct arp_tbl{
	struct arp_tbl *next;
	char ip[128];
	int type;
	int flags;
	char hwa[128];
	char mask[128];
	char dev[128];
};
struct arp_tbl* get_arp_tbl(void);
void free_arp_tbl(struct arp_tbl *tbl);
char* find_ip_tbl(struct arp_tbl *tbl, char *max);

#endif
