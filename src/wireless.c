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
#include "wutil.h"

#define SSID_MAX_SIZE 32
#define IFACE(band, key)        band? "wireless.@wifi-iface[1]."#key : "wireless.@wifi-iface[0]."#key
#define RADIO(band, key)        band? "wireless.radio1."#key : "wireless.radio0."#key

static int get_wireless_channel(int client)
{
        char *ifname[2] = {"wlan0", "wlan1"};

        char *cfmt =    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                        "<WIRELESS>"
                                "<INTERFACE>"
                                        "<BAND>2G</BAND>"
                                        "%s"
                                "</INTERFACE>"
                                "<INTERFACE>"
                                        "<BAND>5G</BAND>"
                                        "%s"
                                "</INTERFACE>"
                        "</WIRELESS>";

        char xml[XMLLEN*4] = {0};
        char channel[2][XMLLEN*2] = {{0}, {0}};
        char buf[IWINFO_BUFSIZE] = {0};

        int len, i, k, pos, ch, wlen;
        struct iwinfo_freqlist_entry *e;

        const struct iwinfo_ops *iw;

        for(k=0; k<2; k++){
                iw = iwinfo_backend(ifname[k]);
                if (!iw){
                        continue;
                }
                if (iw->freqlist(ifname[k], buf, &len) || len <= 0){
                        continue;
                }

                if (iw->channel(ifname[k], &ch))
                        ch = -1;

                pos = 0;
                for (i = 0; i < len; i += sizeof(struct iwinfo_freqlist_entry))
                {
                        e = (struct iwinfo_freqlist_entry *) &buf[i];
                        wlen = snprintf(&channel[k][0]+pos,
                                        sizeof(channel[k])-pos,
                                        "<CHANNEL>%s %s (Channel %s)%s</CHANNEL>",
                                        (ch == e->channel) ? "*" : " ",
                                        format_frequency(e->mhz),
                                        format_channel(e->channel),
                                        e->restricted ? " [restricted]" : ""
                                        );
                        pos += wlen;
                }
        }

        snprintf(xml, sizeof(xml), cfmt, channel[0], channel[1]);
        write(client, xml, strlen(xml));
        return 0;
}

static int get_wireless_txpower(int client)
{
        char *ifname[2] = {"wlan0", "wlan1"};

        char *cfmt =    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                        "<WIRELESS>"
                                "<INTERFACE>"
                                        "<BAND>2G</BAND>"
                                        "%s"
                                "</INTERFACE>"
                                "<INTERFACE>"
                                        "<BAND>5G</BAND>"
                                        "%s"
                                "</INTERFACE>"
                        "</WIRELESS>";


        int len, pwr, off, i, k, pos, wlen;
        char buf[IWINFO_BUFSIZE];
        struct iwinfo_txpwrlist_entry *e;

        char xml[XMLLEN*4] = {0};
        char txpower[2][XMLLEN*2] = {{0}, {0}};
        const struct iwinfo_ops *iw;

        for(k=0; k<2; k++){
                iw = iwinfo_backend(ifname[k]);
                if (!iw){
                        continue;
                }

                if (iw->txpwrlist(ifname[k], buf, &len) || len <= 0){
                        continue;
                }

                if (iw->txpower(ifname[k], &pwr))
                        pwr = -1;

                printf("Wireless txpower %d %s", pwr, strerror(errno));

                if (iw->txpower_offset(ifname[k], &off))
                        off = 0;

                pos = 0;
                for (i = 0; i < len; i+=sizeof(struct iwinfo_txpwrlist_entry)){
                        e = (struct iwinfo_txpwrlist_entry *) &buf[i];

                        wlen = snprintf(&txpower[k][0]+pos, sizeof(txpower)-pos,
                                        "<TXPOWER>%s%3d dBm (%4d mW)</TXPOWER>",
                                        (pwr == e->dbm) ? "*" : " ",
                                        e->dbm + off,
                                        iwinfo_dbm2mw(e->dbm + off));
                        pos += wlen;
                }
        }

        snprintf(xml, sizeof(xml), cfmt, txpower[0], txpower[1]);
        write(client, xml, strlen(xml));
        return 0;
}

static int get_wireless_country(int client)
{
        char *ifname[2] = {"wlan0", "wlan1"};

        char *cfmt =    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                        "<WIRELESS>"
                                "<INTERFACE>"
                                        "<BAND>2G</BAND>"
                                        "%s"
                                "</INTERFACE>"
                                "<INTERFACE>"
                                        "<BAND>5G</BAND>"
                                        "%s"
                                "</INTERFACE>"
                        "</WIRELESS>";

        int len=0, k=0, pos=0, wlen=0;
        char buf[IWINFO_BUFSIZE];
        char *ccode;
        char curcode[3];
        const struct iwinfo_iso3166_label *l;

        char xml[XMLLEN*32] = {0};
        char country[2][XMLLEN*16] = {{0}, {0}};
        const struct iwinfo_ops *iw;

        for(k=0; k<2; k++){
                iw = iwinfo_backend(ifname[k]);
                if (!iw){
                        continue;
                }

                if (iw->countrylist(ifname[k], buf, &len))
                {
                        continue;
                }

                if (iw->country(ifname[k], curcode))
                        memset(curcode, 0, sizeof(curcode));

                pos = 0;
                for (l = IWINFO_ISO3166_NAMES; l->iso3166; l++){
                        if((ccode=lookup_country(buf, len, l->iso3166))!= NULL){
                                wlen = snprintf(&country[k][0]+pos,
                                                sizeof(country[k])-pos,
                                                "<COUNTRY>%s %4s  %c%c</COUNTRY>",
                                                strncmp(ccode, curcode, 2)?" ":"*",
                                                ccode,
                                                (l->iso3166 / 256),
                                                (l->iso3166 % 256)
                                               );
                                pos += wlen;
                        }
                }
        }

        snprintf(xml, sizeof(xml), cfmt, country[0], country[1]);
        write(client, xml, strlen(xml));
        return 0;
}

static int get_assoc_server(int client)
{
        char *ifname[2] = {"wlan0", "wlan1"};

        char *cfmt =    "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                        "<WIRELESS>"
                                "<INTERFACE>"
                                        "<BAND>2G</BAND>"
                                        "%s"
                                "</INTERFACE>"
                                "<INTERFACE>"
                                        "<BAND>5G</BAND>"
                                        "%s"
                                "</INTERFACE>"
                        "</WIRELESS>";
        char *afmt =    "<CLIENT>"
                                "<SSID>%s</SSID>"
                                "<MAC>%s</MAC>"
                                "<IP>%s</IP>"
                                "<SIGNAL>%s</SIGNAL>"
                                "<NOISE>%s</NOISE>"
                                "<RX_RATE>%s</RX_RATE>"
                                "<TX_RATE>%s</TX_RATE>"
                        "</CLIENT>";

        int i, len, k, pos, wlen;
        char buf[IWINFO_BUFSIZE];
        struct iwinfo_assoclist_entry *e=NULL;

        char xml[XMLLEN*32] = {0}, mac[32] = {0}, *ip=NULL;
        char associate[2][XMLLEN*16] = {{0}, {0}};
        const struct iwinfo_ops *iw=NULL;
        struct arp_tbl *ptbl = get_arp_tbl();

        for(k=0; k<2; k++){
                iw = iwinfo_backend(ifname[k]);
                if (!iw){
                        continue;
                }

                if (iw->assoclist(ifname[k], buf, &len)){
                        continue;
                }else if (len <= 0)
                {
                        continue;
                }

                pos = 0;
                for (i=0; i<len; i+=sizeof(struct iwinfo_assoclist_entry)){
                        e = (struct iwinfo_assoclist_entry *) &buf[i];

                        snprintf(mac, sizeof(mac), "%s", format_bssid(e->mac));
                        wlen = snprintf(&associate[k][0] + pos,
                                        sizeof(associate[k])-pos, afmt,
                                        uci_get_cfg(IFACE(i, ssid),
                                                xml,
                                                sizeof(xml)
                                                ),
                                        mac,
                                        ptbl?((ip=find_ip_tbl(ptbl, mac)) ? ip:"") : "",
                                        format_signal(e->signal),
                                        format_noise(e->noise),
                                        format_assocrate(&e->rx_rate),
                                        format_assocrate(&e->tx_rate));
                        pos += wlen;

                }
        }

        if(ptbl){
                free_arp_tbl(ptbl);
        }
        snprintf(xml, sizeof(xml), cfmt, associate[0], associate[1]);
        write(client, xml, strlen(xml));
        return 0;
}

int get_wireless_server(int client, char *ibuf, int len, char *torken)
{
        char *wfmt = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
                "<WIRELESS>"
                "%s%s"
                "</WIRELESS>";

        char *cfmt =   "<CONFIG>"
                                "<BASE>"
                                        "<BAND>%s</BAND>"
                                        "<DISABLE>%s</DISABLE>"
                                        "<SSID>%s</SSID>"
                                        "<SECURITY>%s</SECURITY>"
                                "</BASE>"
                                "<ADVANCE>"
                                        "<MODE>%s</MODE>"
                                        "<HTMODE>%s</HTMODE>"
                                        "<COUNTRY>%s</COUNTRY>"
                                        "<RTS_CTS>%s</RTS_CTS>"
                                        "<CHANNEL>"
                                                "<CH>%d</CH>"
                                                "<MODE>%s</MODE>"
                                        "</CHANNEL>"
                                        "<TXPOWER>%s</TXPOWER>"
                                        "<HIDESSID>%s</HIDESSID>"
                                        "<WDS>%s</WDS>"
                                "</ADVANCE>"
                        "</CONFIG>";

        char *wepfmt = "<ENCRYPTION>%s</ENCRYPTION>"
                       "<KEY>%s</KEY>"
                       "<KEY1>%s</KEY1>"
                       "<KEY2>%s</KEY2>"
                       "<KEY3>%s</KEY3>"
                       "<KEY4>%s</KEY4>";

        char *wpafmt = "<ENCRYPTION>%s</ENCRYPTION>"
                       "<CIPHER>%s</CIPHER>"
                       "<KEY>%s</KEY>";

        char *ifname[] = {"wlan0", "wlan1"};
        const struct iwinfo_ops *iw = NULL;
        char xml[XMLLEN*2] = {0};
        char config[2][XMLLEN] = {{0}, {0}};
        int i;

        if(ibuf && !strcmp(ibuf, "/channel")){
                return get_wireless_channel(client);
        }

        if(ibuf && !strcmp(ibuf, "/txpower")){
                return get_wireless_txpower(client);
        }

        if(ibuf && !strcmp(ibuf, "/country")){
                return get_wireless_country(client);
        }

        if(ibuf && !strcmp(ibuf, "/associate")){
                return get_assoc_server(client);
        }

        if(!ibuf || strcmp(ibuf, "/config")){
                return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
        }

        for(i=0; i<2; i++){
                char band[4]={0}, disable[2]={0}, ssid[SSID_MAX_SIZE]={0},\
                             channel[8]={0}, txpower[4]={0}, mode[16]={0},\
                             htmode[8]={0}, country[8]={0}, rts[8]={0},\
                             hssid[4]={0};

                char encry[32], security[XMLLEN], wds[4]={0}, interface[32]={0};
                int ch=0;

                iw = iwinfo_backend(ifname[i]);
                snprintf(interface, sizeof(interface), "wireless.@wifi-iface[%d]", i);
                uci_get_cfg(interface, xml, sizeof(xml));
                if(strcmp(xml, "wifi-iface")){
                        continue;
                }
                //if(!iw) continue;
                //Base 
                snprintf(band, sizeof(band), "%s", i==0 ? "2G" : "5G");
                snprintf(disable, sizeof(disable), "%s",
                                uci_get_cfg(RADIO(i, disabled),
                                        xml,
                                        sizeof(xml)
                                        )
                        );

                uci_get_cfg(IFACE(i, ssid), ssid, sizeof(ssid));
                uci_get_cfg(RADIO(i, country), country, sizeof(xml));
                //Advance
                uci_get_cfg(RADIO(i, hwmode), mode, sizeof(mode));
                if(strlen(mode)==0){
                        strcpy(mode, "auto");
                }
                uci_get_cfg(RADIO(i, htmode), htmode, sizeof(htmode));
                uci_get_cfg(RADIO(i, rts), rts, sizeof(rts));
                uci_get_cfg(RADIO(i, channel), channel, sizeof(channel));

                if(!strcmp(channel, "auto")){
                        iw? iw->channel(ifname[i], &ch) : (ch=-1);
                }else{
                        ch = atoi(channel);
                        strcpy(channel, "Manual");
                }
                uci_get_cfg(RADIO(i, txpower), txpower, sizeof(txpower));
                uci_get_cfg(IFACE(i, hidden), hssid, sizeof(hssid));
                uci_get_cfg(IFACE(i, wds), wds, sizeof(wds));
                //Sec
                uci_get_cfg(IFACE(i, encryption), encry, sizeof(encry));

                if(!strncmp(encry, "none", sizeof(encry)) &&
                                (strlen(encry)==strlen("none"))){
                        snprintf(security, sizeof(security), "%s", "<ENCRYPTION>none</ENCRYPTION>");
                }else if((!strncmp(encry, "wep-open", sizeof(encry)) &&
                                (strlen(encry)==strlen("wep-open"))) ||
                                (!strncmp(encry, "wep-shared", sizeof(encry)) &&
                                (strlen(encry)==strlen("wep-shared")))){

                        char index[2], key[4][64], name[32];
                        if(!strcmp(encry, "wep-open"))
                                snprintf(name, sizeof(name), "%s", "WEP Open System");
                        else
                                snprintf(name, sizeof(name), "%s", "WEP Share key");

                        //不对加密方式解析， 有上端自己显示
                        snprintf(name, sizeof(name), "%s", encry);

                        uci_get_cfg(IFACE(i, key), index, sizeof(index));
                        uci_get_cfg(IFACE(i, key1), key[0], sizeof(key[0]));
                        uci_get_cfg(IFACE(i, key2), key[1], sizeof(key[1]));
                        uci_get_cfg(IFACE(i, key3), key[2], sizeof(key[2]));
                        uci_get_cfg(IFACE(i, key4), key[3], sizeof(key[3]));

                        snprintf(security, sizeof(security), wepfmt,
                                        name,
                                        index,
                                        key[0][0]=='s' ? &key[0][0]+2 : key[0],
                                        key[1][0]=='s' ? &key[1][0]+2 : key[1],
                                        key[2][0]=='s' ? &key[2][0]+2 : key[2],
                                        key[3][0]=='s' ? &key[3][0]+2 : key[3]
                                        );

                }else if(!strncmp(encry, "psk", strlen("psk"))){
                        char name[32], cipher[16], key[128], *ptr = NULL;
                        if(!strncmp(encry, "psk2", strlen("psk2"))){
                                snprintf(name, sizeof(name), "%s", "WPA2-PSK");
                        }else if(!strncmp(encry, "psk-mix", strlen("psk-mix"))){
                                snprintf(name, sizeof(name), "%s", "WPA-PSK/WPA2-PSK");
                        }else{
                                snprintf(name, sizeof(name), "%s", "WPA-PSK");
                        }

                        ptr = strchr(encry, '+');
                        if(!ptr){
                                snprintf(cipher, sizeof(cipher), "%s", "auto");
                                //不对加密方式解析， 有上端自己显示
                                snprintf(name, sizeof(name), "%s", encry);
                        }else{
                                snprintf(cipher, sizeof(cipher), "%s", ptr+1);
                                //不对加密方式解析， 有上端自己显示
                                *ptr = 0;
                                snprintf(name, sizeof(name), "%s", encry);
                        }
                        uci_get_cfg(IFACE(i, key), key, sizeof(key));

                        snprintf(security, sizeof(security),
                                        wpafmt,
                                        name,
                                        cipher,
                                        key
                                        );
                }

                snprintf(config[i], sizeof(config[i]), cfmt,
                                band,
                                disable,
                                ssid,
                                security,
                                mode,
                                htmode,
                                country,
                                rts,
                                ch,
                                channel,
                                txpower,
                                hssid,
                                wds
                        );
        }
        snprintf(xml, sizeof(xml), wfmt, config[0], config[1]);

        write(client, xml, strlen(xml));
        return 0;
}

static int check_security_arg(ezxml_t sec)
{
        ezxml_t encry=NULL, cipher=NULL, key=NULL;
        if(NULL == (encry = ezxml_child(sec, "ENCRYPTION"))){
                return 1;
        }

        if(!strcmp(encry->txt, "none")){
                return 0;
        }

        if(!strcmp(encry->txt, "psk") ||
           !strcmp(encry->txt, "psk2") ||
           !strcmp(encry->txt, "psk-mix")){
                cipher = ezxml_child(sec, "CIPHER");
                key    = ezxml_child(sec, "KEY");
                if(!key || !cipher){
                        return 1;
                }
                if(!strcmp(cipher->txt, "tkip") ||
                   !strcmp(cipher->txt, "ccmp") ||
                   !strcmp(cipher->txt, "tkip+ccmp")||
                   !strcmp(cipher->txt, "auto")){
                        if(0==strlen(key->txt)){
                                return 1;
                        }
                        return 0;
                }
                return 1;
        }

        if(!strcmp(encry->txt, "wep-open") ||
           !strcmp(encry->txt, "wep-shared")){
                ezxml_t key=NULL;
                char *key_id[]={"KEY1", "KEY2", "KEY3", "KEY4"};
                int  i=0, idx=0, key_len=0, idx_flag=1, k=0;

                key = ezxml_child(sec, "KEY");

                if((key==NULL)          ||
                   (NULL==key->txt)     ||
                   (1!=strlen(key->txt))||
                   !isdigit(*key->txt)  ||
                   ((idx=atoi(key->txt))>4)||
                   (idx==0)){
                        return 1;
                }

                for(i=0; i<4; i++){
                        key = ezxml_child(sec, key_id[i]);
                        if(key && key->txt){
                                key_len = strlen(key->txt);
                                if((key_len==5) || (key_len==13)){
                                        for(k=0; k<key_len; k++){
                                                if(!isascii(key->txt[k])){
                                                        return 1;
                                                }
                                        }
                                }
                                if((key_len==10) || (key_len==26)){
                                        for(k=0; k<key_len; k++){
                                                if(!isxdigit(key->txt[k])){
                                                        return 1;
                                                }
                                        }
                                }
                                if((idx-1)==i){
                                        idx_flag = 0;
                                }
                        }
                }
                return idx_flag;
        }

        return 1;
}

static int check_base_arg(ezxml_t base)
{
        ezxml_t security=NULL, band=NULL, disable=NULL, ssid=NULL;

        security = ezxml_child(base, "SECURITY");
        band     = ezxml_child(base, "BAND");
        disable  = ezxml_child(base, "DISABLE");
        ssid     = ezxml_child(base, "SSID");
        //channel        = ezxml_child(base, "CHANNEL");
        //txpower  = ezxml_child(base, "TXPOWER");

        if(!security || !band || !disable || !ssid){
                return 1;
        }

        if(check_security_arg(security)){
                return 1;
        }

        if(!band->txt ||
           (strcmp(band->txt, "2G") &&
           strcmp(band->txt, "5G"))){
                return 1;
        }

        if(!disable->txt[0] ||
           (1!=strlen(disable->txt))||
           ((*disable->txt!='0') && (*disable->txt!='1'))){
                return 1;
        }

        return 0;
}

static int check_advance_arg(ezxml_t advance)
{
        return 0;
}

static int set_security_arg(ezxml_t security, int BG)
{
        ezxml_t encryption=ezxml_child(security, "ENCRYPTION");

        if(!encryption){
                return 1;
        }

        if(!strcmp(encryption->txt, "none")){
                uci_set_cfg(IFACE(BG, encryption), "none");
                return 0;
        }

        if(!strcmp(encryption->txt, "psk") ||
           !strcmp(encryption->txt, "psk2") ||
           !strcmp(encryption->txt, "psk-mix")){

                ezxml_t cipher=NULL, key=NULL;
                char encry[32]={0};

                cipher = ezxml_child(security, "CIPHER");
                key    = ezxml_child(security, "KEY");
                if(!strcmp(cipher->txt, "auto")){
                        snprintf(encry, sizeof(encry), "%s",
                                        encryption->txt
                                );
                }else{
                        snprintf(encry, sizeof(encry), "%s+%s",
                                        encryption->txt,
                                        cipher->txt
                                );
                }

                uci_set_cfg(IFACE(BG, encryption), encry);
                uci_set_cfg(IFACE(BG, key), key->txt);
                return 0;
        }

        if(!strcmp(encryption->txt, "wep-open") ||
           !strcmp(encryption->txt, "wep-shared")){
                ezxml_t key=NULL, key1=NULL, key2=NULL, key3=NULL, key4=NULL;
                char passwd[64];

                key  = ezxml_child(security, "KEY");
                key1 = ezxml_child(security, "key1");
                key2 = ezxml_child(security, "key2");
                key3 = ezxml_child(security, "key3");
                key4 = ezxml_child(security, "key4");

                uci_set_cfg(IFACE(BG, key),  key->txt);

                snprintf(passwd, sizeof(passwd), "s:%s", key1->txt);
                uci_set_cfg(IFACE(BG, key1), passwd);

                snprintf(passwd, sizeof(passwd), "s:%s", key2->txt);
                uci_set_cfg(IFACE(BG, key2), passwd);

                snprintf(passwd, sizeof(passwd), "s:%s", key3->txt);
                uci_set_cfg(IFACE(BG, key3), passwd);

                snprintf(passwd, sizeof(passwd), "s:%s", key4->txt);
                uci_set_cfg(IFACE(BG, key4), passwd);
                return 0;
        }

        return 0;
}

static int set_base_arg(ezxml_t base, int BG)
{
        ezxml_t security=NULL, disable=NULL, ssid=NULL;

        security = ezxml_child(base, "SECURITY");
        disable  = ezxml_child(base, "DISABLE");
        ssid     = ezxml_child(base, "SSID");

        disable->txt[0]=='1'? uci_set_cfg(RADIO(BG, disabled), disable->txt):
                uci_set_cfg(RADIO(BG, disabled), "");
        uci_set_cfg(IFACE(BG, ssid), ssid->txt);
        set_security_arg(security, BG);
        return 0;
}

static int set_advance_arg(ezxml_t advance, int BG)
{
        ezxml_t mode=NULL, htmode=NULL, rts=NULL, channel=NULL, country=NULL,\
                     hidden=NULL, txpower=NULL, wds=NULL;

        mode   = ezxml_child(advance, "MODE");
        htmode = ezxml_child(advance, "HTMODE");
        rts    = ezxml_child(advance, "RTS_CTS");
        country = ezxml_child(advance, "COUNTRY");
        channel  = ezxml_child(advance, "CHANNEL");
        txpower  = ezxml_child(advance, "TXPOWER");
        hidden = ezxml_child(advance, "HIDESSID");
        wds = ezxml_child(advance, "WDS");


        if(!strcmp(mode->txt, "auto")){
                uci_set_cfg(RADIO(BG, hwmode), "");
        }else{
                uci_set_cfg(RADIO(BG, hwmode), mode->txt);
        }
        uci_set_cfg(RADIO(BG, htmode), htmode->txt);
        uci_set_cfg(RADIO(BG, rts), rts->txt);
        uci_set_cfg(RADIO(BG, country), country->txt);
        uci_set_cfg(RADIO(BG, channel), channel->txt);
        uci_set_cfg(RADIO(BG, txpower), txpower->txt);
        hidden->txt[0]=='1'? uci_set_cfg(IFACE(BG, hidden), hidden->txt) :
               uci_set_cfg(IFACE(BG, hidden), "");
        wds->txt[0]=='1'? uci_set_cfg(IFACE(BG, wds), wds->txt) :
               uci_set_cfg(IFACE(BG, wds), "");

        return 0;
}

int post_wireless_server(int client, char *inbuf, int len, char *subtok)
{
        int BG=0;

        if(strncmp(subtok, "/config", inbuf-subtok)){
                return response_state(client, NO_SERVICE, err_msg[NO_SERVICE]);
        }

        ezxml_t root = NULL, config=NULL;

        root = ezxml_parse_str(inbuf, len);
        if(!root){
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }
        if(root && *ezxml_error(root)) {
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

        if(NULL == (config=ezxml_child(root, "CONFIG"))){
                ezxml_free(root);
                return response_state(client, FORMAT_ERR, err_msg[FORMAT_ERR]);
        }

        for(; config; config=config->next){
                ezxml_t base=NULL, advance=NULL;

                if(NULL == (base=ezxml_child(config, "BASE"))){
                        ezxml_free(root);
                        return response_state(client, FORMAT_ERR,
                                        err_msg[FORMAT_ERR]
                                        );
                }

                if(check_base_arg(base)){
                        ezxml_free(root);
                        return response_state(client, FORMAT_ERR, "check base arg error");
                }

                advance = ezxml_child(config, "ADVANCE");
                if(advance){
                        if(check_advance_arg(advance)){
                                ezxml_free(root);
                                return response_state(client, FORMAT_ERR,
                                                err_msg[FORMAT_ERR]
                                                );
                        }
                }
        }

        config = ezxml_child(root, "CONFIG");
        for(; config; config=config->next){
                ezxml_t base=NULL, advance=NULL;

                base=ezxml_child(config, "BASE");
                advance = ezxml_child(config, "ADVANCE");

                if(!strcmp(ezxml_child(base, "BAND")->txt, "2G")){
                        BG=0;
                }else{
                        BG=1;
                }

                set_base_arg(base, BG);
                if(advance){
                        set_advance_arg(advance, BG);
                }
        }
        ezxml_free(root);

        uci_commit_change("wireless");
        system("/sbin/wifi restart");
        return 0;
}
