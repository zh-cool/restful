/*
 * =====================================================================================
 *
 *       Filename:  wclient.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  12/10/2013 12:10:38 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
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
#include <iwinfo.h>
#include "restful.h"
#include "service.h"
#include "ezxml.h"
#include "xmlerror.h"
#include "errno.h"
#include "util.h"
static char * format_signal(int sig)
{
	static char buf[10];

	if (!sig)
		snprintf(buf, sizeof(buf), "unknown");
	else
		snprintf(buf, sizeof(buf), "%d dBm", sig);

	return buf;
}

static char * format_noise(int noise)
{
	static char buf[10];

	if (!noise)
		snprintf(buf, sizeof(buf), "unknown");
	else
		snprintf(buf, sizeof(buf), "%d dBm", noise);

	return buf;
}

static char * format_rate(int rate)
{
	static char buf[14];

	if (rate <= 0)
		snprintf(buf, sizeof(buf), "unknown");
	else
		snprintf(buf, sizeof(buf), "%d.%d MBit/s",
				rate / 1000, (rate % 1000) / 100);                                                                                                                               

	return buf;
}

static char * format_assocrate(struct iwinfo_rate_entry *r)
{
	static char buf[40];
	char *p = buf;
	int l = sizeof(buf);

	if (r->rate <= 0)
	{
		snprintf(buf, sizeof(buf), "unknown");
	}
	else
	{
		p += snprintf(p, l, "%s", format_rate(r->rate));
		l = sizeof(buf) - (p - buf);

		if (r->mcs >= 0)
		{
			p += snprintf(p, l, ", MCS %d, %dMHz", r->mcs, 20 + r->is_40mhz*20);
			l = sizeof(buf) - (p - buf);

			if (r->is_short_gi)
				p += snprintf(p, l, ", short GI");
		}
	}

	return buf;
}

static char * format_ssid(char *ssid)
{
	static char buf[IWINFO_ESSID_MAX_SIZE+3];

	if (ssid && ssid[0])
		snprintf(buf, sizeof(buf), "\"%s\"", ssid);
	else
		snprintf(buf, sizeof(buf), "unknown");

	return buf;
}

static char * format_channel(int ch)
{
	static char buf[8];

	if (ch <= 0)
		snprintf(buf, sizeof(buf), "unknown");
	else
		snprintf(buf, sizeof(buf), "%d", ch);

	return buf;
}

static char * format_enc_ciphers(int ciphers)
{
	static char str[128] = { 0 };
	char *pos = str;

	if (ciphers & IWINFO_CIPHER_WEP40)
		pos += sprintf(pos, "WEP-40, ");

	if (ciphers & IWINFO_CIPHER_WEP104)
		pos += sprintf(pos, "WEP-104, ");

	if (ciphers & IWINFO_CIPHER_TKIP)
		pos += sprintf(pos, "TKIP, ");

	if (ciphers & IWINFO_CIPHER_CCMP)
		pos += sprintf(pos, "CCMP, ");

	if (ciphers & IWINFO_CIPHER_WRAP)
		pos += sprintf(pos, "WRAP, ");

	if (ciphers & IWINFO_CIPHER_AESOCB)
		pos += sprintf(pos, "AES-OCB, ");

	if (ciphers & IWINFO_CIPHER_CKIP)
		pos += sprintf(pos, "CKIP, ");

	if (!ciphers || (ciphers & IWINFO_CIPHER_NONE))
		pos += sprintf(pos, "NONE, ");

	*(pos - 2) = 0;

	return str;
}

static char * format_enc_suites(int suites)
{
	static char str[64] = { 0 };
	char *pos = str;

	if (suites & IWINFO_KMGMT_PSK)
		pos += sprintf(pos, "PSK/");

	if (suites & IWINFO_KMGMT_8021x)
		pos += sprintf(pos, "802.1X/");

	if (!suites || (suites & IWINFO_KMGMT_NONE))
		pos += sprintf(pos, "NONE/");

	*(pos - 1) = 0;

	return str;
}

static char * format_encryption(struct iwinfo_crypto_entry *c)
{
	static char buf[512];

	if (!c)
	{
		snprintf(buf, sizeof(buf), "unknown");
	}
	else if (c->enabled)
	{
		/*  WEP */
		if (c->auth_algs && !c->wpa_version)
		{
			if ((c->auth_algs & IWINFO_AUTH_OPEN) &&
					(c->auth_algs & IWINFO_AUTH_SHARED))
			{
				snprintf(buf, sizeof(buf), "WEP Open/Shared (%s)",
						format_enc_ciphers(c->pair_ciphers));
			}
			else if (c->auth_algs & IWINFO_AUTH_OPEN)
			{
				snprintf(buf, sizeof(buf), "WEP Open System (%s)",
						format_enc_ciphers(c->pair_ciphers));
			}
			else if (c->auth_algs & IWINFO_AUTH_SHARED)
			{
				snprintf(buf, sizeof(buf), "WEP Shared Auth (%s)",
						format_enc_ciphers(c->pair_ciphers));
			}
		}

		/*  WPA */
		else if (c->wpa_version)
		{
			switch (c->wpa_version) {
				case 3:
					snprintf(buf, sizeof(buf), "mixed WPA/WPA2 %s (%s)",
							format_enc_suites(c->auth_suites),
							format_enc_ciphers(c->pair_ciphers | c->group_ciphers));
					break;

				case 2:
					snprintf(buf, sizeof(buf), "WPA2 %s (%s)",
							format_enc_suites(c->auth_suites),
							format_enc_ciphers(c->pair_ciphers | c->group_ciphers));
					break;

				case 1:
					snprintf(buf, sizeof(buf), "WPA %s (%s)",
							format_enc_suites(c->auth_suites),
							format_enc_ciphers(c->pair_ciphers | c->group_ciphers));
					break;
			}
		}
		else
		{
			snprintf(buf, sizeof(buf), "none");
		}
	}
	else
	{
		snprintf(buf, sizeof(buf), "none");
	}

	return buf;
}

static int get_ap_list(int client)
{
	char *head = 
		"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		"<WCLIENT>";

	char *apfmt = 
		"<AP>"
			"<BAND>%s</BAND>"
			"<SSID>%s</SSID>"
			"<ENCRYPTION>%s</ENCRYPTION>"
			"<CHANNEL>%s</CHANNEL>"
		"</AP>";


	char *ifname[] = {"wlan0", "wlan1"};
	char *band[] = {"2G", "5G"};
	char xml[XMLLEN*16] = {0};
	char buf[XMLLEN*24];
	const struct iwinfo_ops *iw=NULL;
	struct iwinfo_scanlist_entry *e=NULL;
	int length=0, pos=0, i=0, k=0, x=0, len=0;
	
	pos = sprintf(xml, "%s", head);
	for(k=0; k<2; k++){
		iw = iwinfo_backend(ifname[k]);
		if(!iw) continue;

		if (iw->scanlist(ifname[k], buf, &len)){
			continue;
		}

		for (i = 0, x = 1; i < len; i += sizeof(struct iwinfo_scanlist_entry), x++){
			e = (struct iwinfo_scanlist_entry *) &buf[i];

			length = snprintf(xml+pos, sizeof(xml)-pos, apfmt, 
					band[k],
					format_ssid(e->ssid),
					format_encryption(&e->crypto),
					format_channel(e->channel)
				      );

			pos += length;
		}
	}
	strncat(xml+pos, "</WCLIENT>", sizeof(xml)-pos);

	write(client, xml, strlen(xml));
	return 0;
}

static int get_wclient_config(client)
{
	char *cfmt = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		     "<WCLIENT>"
		     	"<AP>"
				"<BAND>2G</BAND>"
				"<SSID>%s</SSID>"
				"%s"
				"<ASSOCIATE>"
					"<SIGNAL>%s</SIGNAL>"
					"<NOISE>%s</NOISE>"
					"<RX_RATE>%s</RX_RATE>"
					"<TX_RATE>%s</TX_RATE>"
					"<CHANNEL>%d</CHANNEL>"
				"</ASSOCIATE>"
			"</AP>"
		     "</WCLIENT>";

	char *wpafmt = "<SECURITY>"
				"<ENCRYPTION>%s</ENCRYPTION>"
				"<KEY>%s</KEY>"
		       "</SECURITY>";	

	char *wepfmt = "<SECURITY>"
				"<ENCRYPTION>%s</ENCRYPTION>"
				"<KEY>%s</KEY>"
				"<KEY1>%s</KEY1>"
				"<KEY2>%s</KEY2>"
				"<KEY3>%s</KEY3>"
				"<KEY4>%s</KEY4>"
		       "</SECURITY>";	       

	char *noassoci ="<?xml version=\"1.0\" encoding=\"utf-8\"?>"
		     	"<WCLIENT>"
		     		"<AP>"
		     		"</AP>"
		     	"</WCLIENT>";

	char ssid[64]={0}, encry[16]={0}, key[64]={0}, ifname[16]={0};
	char xml[XMLLEN] = {0};
	char security[XMLLEN] = {0};

	struct iwinfo_assoclist_entry *e=NULL;
	const struct iwinfo_ops *iw=NULL;

	uci_get_cfg("wireless.@wifi-iface[2].mode", xml, sizeof(xml));
	if(strcmp(xml, "sta")){
		strcpy(xml, noassoci);
		write(client, xml, sizeof(xml));
		return 0;
	}

	uci_get_cfg("wireless.@wifi-iface[2].ssid", ssid, sizeof(ssid));
	uci_get_cfg("wireless.@wifi-iface[2].encryption", encry, sizeof(encry));
	uci_get_cfg("wireless.@wifi-iface[2].key", key, sizeof(key));
	uci_get_cfg("network.wan.ifname", ifname, sizeof(ifname));

	if(!strcmp(encry, "wep-open") || !strcmp(encry, "wep-shared")){
		char wepkey[4][64];
		snprintf(wepkey[0], sizeof(wepkey[0]), "%s", uci_get_cfg("wireless.@wifi-iface[2].key1", xml, sizeof(xml)));
		snprintf(wepkey[1], sizeof(wepkey[1]), "%s", uci_get_cfg("wireless.@wifi-iface[2].key2", xml, sizeof(xml)));
		snprintf(wepkey[2], sizeof(wepkey[2]), "%s", uci_get_cfg("wireless.@wifi-iface[2].key3", xml, sizeof(xml)));
		snprintf(wepkey[3], sizeof(wepkey[3]), "%s", uci_get_cfg("wireless.@wifi-iface[2].key4", xml, sizeof(xml)));
		snprintf(security, sizeof(security), wepfmt, 
				encry, 
				key, 
				wepkey[0][0]=='s' ? &wepkey[0][0]+2 : wepkey[0], 
				wepkey[1][0]=='s' ? &wepkey[1][0]+2 : wepkey[1], 
				wepkey[2][0]=='s' ? &wepkey[2][0]+2 : wepkey[2], 
				wepkey[3][0]=='s' ? &wepkey[3][0]+2 : wepkey[3]
			);
	}else if(!strcmp(encry, "none")){
		strcpy(security, "<SECURITY><ENCRYPTION>none</ENCRYPTION></SECURITY>");
	}else{
		snprintf(security, sizeof(security), wpafmt, 
				encry,
				key
			);

	}

	iw = iwinfo_backend(ifname);
	if(!iw){
		strcpy(xml, noassoci);
		write(client, xml, sizeof(xml));
		return 0;
	}

	char buf[XMLLEN]={0};
	int len=0, ch=0;

	if (iw->assoclist(ifname, buf, &len) || (len<=0)){
		strcpy(xml, noassoci);
		write(client, xml, sizeof(xml));
		return 0;
	}

	if (iw->channel(ifname, &ch)){
		ch = -1;	
	}

	e = (struct iwinfo_assoclist_entry *) &buf[0];
	snprintf(xml, sizeof(xml), cfmt, 
			ssid,
			security,
			format_signal(e->signal),
			format_noise(e->noise),
			format_assocrate(&e->rx_rate),
			format_assocrate(&e->tx_rate),
			ch
		);

	write(client, xml, strlen(xml));
	return 0;
}

int get_wclient_server(int client, char *ibuf, int len, char *torken)
{
	if(ibuf && !strcmp(ibuf, "/config")){
		return get_wclient_config(client);
	}

	if(ibuf && !strcmp(ibuf, "/scan")){
		return get_ap_list(client);
	}

	return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
}

static int associate_ap(int client, ezxml_t ap)
{
	if(!ap){
		return response_state(client, FORMAT_ERR, "need ap node");
	}

	char *ifname[] = {"wlan0-1", "wlan1-1"};
	char *device[] = {"radio0", "radio1"};
	char xml[32]={0};

	ezxml_t band=NULL, ssid=NULL, sec=NULL, encry=NULL, key=NULL, channel=NULL;
	int iface = 0;

	band = ezxml_child(ap, "BAND");
	ssid = ezxml_child(ap, "SSID");
	channel = ezxml_child(ap, "CHANNEL");

	if((sec=ezxml_child(ap, "SECURITY"))){
		encry = ezxml_child(sec, "ENCRYPTION");
		key = ezxml_child(sec, "KEY");
	}

	if(!(band && ssid && encry && channel && sec)){
		return response_state(client, FORMAT_ERR, "lose node");
	}

	if(!(band->txt[0] && ssid->txt[0] && encry->txt[0] && key->txt[0] && channel->txt[0])){
		return response_state(client, FORMAT_ERR, "lose value");
	}

	if(!strcmp(band->txt, "2G"))
		iface = 0;
	else{
		iface = 1;
	}

	uci_get_cfg("wireless.@wifi-iface[-1].mode", xml, sizeof(xml));
	if(!strcmp(xml, "sta")){
		system("/sbin/uci delete wireless.@wifi-iface[-1]");
	}
	
	system("/sbin/uci add wireless wifi-iface");
	uci_set_cfg("wireless.@wifi-iface[-1].device", device[iface]);
	uci_set_cfg("wireless.@wifi-iface[-1].ssid", ssid->txt);
	uci_set_cfg("wireless.@wifi-iface[-1].mode", "sta");
	uci_set_cfg("wireless.@wifi-iface[-1].network", "wan");
	uci_set_cfg("wireless.@wifi-iface[-1].encryption", encry->txt);
	uci_set_cfg("wireless.@wifi-iface[-1].key", key ? key->txt:"");
	if(!strcmp(encry->txt, "wep-open") || !strcmp(encry->txt, "wep-shared")){
		ezxml_t  key1=NULL, key2=NULL, key3=NULL, key4=NULL;
		char passwd[64] = {0};

		key1 = ezxml_child(sec, "key1");
		key2 = ezxml_child(sec, "key2");
		key3 = ezxml_child(sec, "key3");
		key4 = ezxml_child(sec, "key4");

		snprintf(passwd, sizeof(passwd), "s:%s", key1 ? key1->txt:"");
		uci_set_cfg("wireless.@wifi-iface[-1].key1", passwd);

		snprintf(passwd, sizeof(passwd), "s:%s", key2 ? key2->txt:"");
		uci_set_cfg("wireless.@wifi-iface[-1].key2", passwd);

		snprintf(passwd, sizeof(passwd), "s:%s", key3 ? key3->txt:"");
		uci_set_cfg("wireless.@wifi-iface[-1].key3", passwd);

		snprintf(passwd, sizeof(passwd), "s:%s", key4 ? key4->txt:"");
		uci_set_cfg("wireless.@wifi-iface[-1].key4", passwd);
	}

	uci_set_cfg("network.wan.ifname", ifname[iface]);

	system("/sbin/uci commit wireless");
	system("/sbin/uci commit network");
	system("/etc/init.d/network restart");
	return 0;
}

static int deauthenticated_ap(int client)
{
	char xml[32]={0};
	uci_get_cfg("wireless.@wifi-iface[-1].mode", xml, sizeof(xml));
	if(!strcmp(xml, "sta")){
		system("/sbin/uci delete wireless.@wifi-iface[-1]");
	}else{
		return 0;
	}
	uci_set_cfg("network.wan.ifname", "eth0.2");

	system("/sbin/uci commit wireless");
	system("/sbin/uci commit network");
	system("/etc/init.d/network restart");
	return 0;
}

int post_wclient_server(int client, char *ibuf, int len, char *torken)
{
	if(torken){
		return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
	}

	ezxml_t root = NULL, act=NULL, ap=NULL;
	int ret=0;

	root = ezxml_parse_str(ibuf, len);
	if(!root){
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
	}
        if(root && *ezxml_error(root)) {
		ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

	act = ezxml_child(root, "ACT");
	ap = ezxml_child(root, "AP");

	if(act && !strcmp(act->txt, "associate")){
		ret = associate_ap(client, ap);
	}else if(act && !strcmp(act->txt, "deauthenticated")){
		ret = deauthenticated_ap(client);
	}else{
		ezxml_free(root);
		return response_state(client, FORMAT_ERR, "unknow active");
	}

	ezxml_free(root);
	return ret;
}
