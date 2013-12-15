#ifndef _WUTIL_H_
#define _WUTIL_H_

#include <iwinfo.h>

char* format_ssid(unsigned char *mac);
char* format_channel(int ch);
char* format_frequency(int freq);
char* format_signal(int sig);
char* format_noise(int noise);
char* format_rate(int rate);
char* format_assocrate(struct iwinfo_rate_entry *r);
char* format_bssid(unsigned char *mac);
char* lookup_country(char *buf, int len, int iso3166);
char* format_channel(int ch);
char* format_enc_ciphers(int ciphers);
char* format_enc_suites(int suites);
char* format_encryption(struct iwinfo_crypto_entry *c);

#endif
