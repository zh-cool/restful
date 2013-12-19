#ifndef _ENCRY_H_
#define _ENCRY_H_
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/rand.h>

#define KEYLEN          16
#define SYSKEY          3134
struct sys_key{
        unsigned char *key[KEYLEN];
        unsigned char *iv_enc[AES_BLOCK_SIZE];
        unsigned char *iv_dec[AES_BLOCK_SIZE];
};

int init_shm();

#endif
