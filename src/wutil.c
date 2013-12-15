#include "wutil.h"
char* format_ssid(unsigned char *ssid)
{
        static char buf[IWINFO_ESSID_MAX_SIZE+3];

        if (ssid && ssid[0])
                snprintf(buf, sizeof(buf), "\"%s\"", ssid);
        else
                snprintf(buf, sizeof(buf), "unknown");

        return buf;
}

char* format_channel(int ch)
{
        static char buf[8];

        if (ch <= 0)
                snprintf(buf, sizeof(buf), "unknown");
        else
                snprintf(buf, sizeof(buf), "%d", ch);

        return buf;
}

char* format_frequency(int freq)
{
        static char buf[10];

        if (freq <= 0)
                snprintf(buf, sizeof(buf), "unknown");
        else
                snprintf(buf, sizeof(buf), "%.3f GHz", ((float)freq / 1000.0));

        return buf;
}

char* format_signal(int sig)
{
        static char buf[10];

        if (!sig)
                snprintf(buf, sizeof(buf), "unknown");
        else
                snprintf(buf, sizeof(buf), "%d dBm", sig);

        return buf;
}

char* format_noise(int noise)
{
        static char buf[10];

        if (!noise)
                snprintf(buf, sizeof(buf), "unknown");
        else
                snprintf(buf, sizeof(buf), "%d dBm", noise);

        return buf;
}

char* format_rate(int rate)
{
        static char buf[14];

        if (rate <= 0)
                snprintf(buf, sizeof(buf), "unknown");
        else
                snprintf(buf, sizeof(buf), "%d.%d MBit/s",
                                rate / 1000, (rate % 1000) / 100);

        return buf;
}

char* format_assocrate(struct iwinfo_rate_entry *r)
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
                        p += snprintf(p, l, ", MCS %d, %dMHz",
                                        r->mcs,
                                        20 + r->is_40mhz*20
                                        );
                        l = sizeof(buf) - (p - buf);

                        if (r->is_short_gi)
                                p += snprintf(p, l, ", short GI");
                }
        }

        return buf;
}

char* format_bssid(unsigned char *mac)
{
        static char buf[18];

        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        return buf;
}

char* lookup_country(char *buf, int len, int iso3166)
{
        int i;
        struct iwinfo_country_entry *c;

        for (i = 0; i < len; i += sizeof(struct iwinfo_country_entry))
        {
                c = (struct iwinfo_country_entry *) &buf[i];

                if (c->iso3166 == iso3166)
                        return c->ccode;
        }

        return NULL;
}

char* format_enc_ciphers(int ciphers)
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

char* format_enc_suites(int suites)
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

char* format_encryption(struct iwinfo_crypto_entry *c)
{
        static char buf[512];

        if (!c){
                snprintf(buf, sizeof(buf), "unknown");
        }else if (c->enabled){
                /*  WEP */
                if (c->auth_algs && !c->wpa_version){
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
                else if (c->wpa_version){
                        switch (c->wpa_version) {
                        case 3:
                                snprintf(buf, sizeof(buf), "mixed WPA/WPA2 %s (%s)",
                                         format_enc_suites(c->auth_suites),
                                         format_enc_ciphers(c->pair_ciphers |
                                                 c->group_ciphers)
                                         );
                                break;

                        case 2:
                                snprintf(buf, sizeof(buf), "WPA2 %s (%s)",
                                         format_enc_suites(c->auth_suites),
                                         format_enc_ciphers(c->pair_ciphers |
                                                 c->group_ciphers)
                                         );
                                break;

                        case 1:
                                snprintf(buf, sizeof(buf), "WPA %s (%s)",
                                         format_enc_suites(c->auth_suites),
                                         format_enc_ciphers(c->pair_ciphers |
                                                 c->group_ciphers)
                                         );
                                break;
                        }
                }else{
                        snprintf(buf, sizeof(buf), "none");
                }
        }
        else{
                snprintf(buf, sizeof(buf), "none");
        }

        return buf;
}

