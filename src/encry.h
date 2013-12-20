#ifndef _ENCRY_H_
#define _ENCRY_H_
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define KEYLEN          16
#define SYSKEY          3134
struct sys_key{
        unsigned char key[KEYLEN];
        unsigned char iv_enc[AES_BLOCK_SIZE];
        unsigned char iv_dec[AES_BLOCK_SIZE];
};

int init_shm();
void* get_shm();
int encpry(char *ibuf, int len);
int decpry(char *ibuf, int len);
#endif
