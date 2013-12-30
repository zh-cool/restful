#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "encry.h"

#define KEYFILE         "/tmp/keyfile"
#define FILEMODE        (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)

int encpry(char *ibuf, int len)
{
        struct sys_key *pskey = get_shm();
        struct sys_key skey;
        memcpy(&skey, pskey, sizeof(struct sys_key));
        AES_KEY enc_key;

        const size_t encslength = len%AES_BLOCK_SIZE?
                (len/AES_BLOCK_SIZE+1) * AES_BLOCK_SIZE: len;
        unsigned char enc_out[encslength+1];

        AES_set_encrypt_key(skey.key, KEYLEN*8, &enc_key);
        AES_cbc_encrypt(ibuf, enc_out, len, &enc_key, skey.iv_enc,
                        AES_ENCRYPT);

        memcpy(ibuf, enc_out, encslength);
        ibuf[encslength] = 0;
        return encslength;
}

int decpry(char *ibuf, int len)
{
        struct sys_key *pskey = get_shm();
        struct sys_key skey;
        memcpy(&skey, pskey, sizeof(struct sys_key));
        AES_KEY dec_key;
        unsigned char dec_out[len];
        memset(dec_out, 0, len);

        AES_set_decrypt_key(skey.key, KEYLEN*8, &dec_key);
        AES_cbc_encrypt(ibuf, dec_out, len, &dec_key, skey.iv_dec,
                                                AES_DECRYPT);

        memcpy(ibuf, dec_out, len);
        return 0;
}


int create_keyfile(const unsigned char *key)
{
        int fd = 0;
        unsigned char md[512];
        if((fd = open(KEYFILE, O_RDWR|O_CREAT|O_TRUNC, FILEMODE)) < 0 ){
                return -1;
        }

        struct sys_key aeskey;
        SHA256(key, strlen(key), md);
        memcpy(aeskey.key, md, KEYLEN);

        memcpy(aeskey.iv_enc, md+KEYLEN, AES_BLOCK_SIZE);
        memcpy(aeskey.iv_dec, md+KEYLEN, AES_BLOCK_SIZE);

        write(fd, &aeskey, sizeof(aeskey));
        close(fd);
        return 0;
}

int init_shm()
{
        int fd = 0;
        if(access(KEYFILE, F_OK) < 0){
                if(errno == ENOENT){
                        create_keyfile("111111");
                }
        }

        if((fd=open(KEYFILE, O_RDWR, 0666)) < 0){
                return -1;
        }

        key_t key=SYSKEY;
        int shmid;
        char *shm = NULL;

        /*
         *      * Create the segment.
         */
        if ((shmid=shmget(key, sizeof(struct sys_key), IPC_CREAT | 0666)) < 0){
                exit(1);
        }

        /*
         *      * Now we attach the segment to our data space.
         */
        if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
                exit(1);
        }

        read(fd, shm, sizeof(struct sys_key));
        close(fd);
        return 0;
}

void* get_shm()
{
        static char *shm=NULL;
        if(shm){
                return shm;
        }

        key_t key=SYSKEY;
        int shmid;
        if ((shmid=shmget(key, sizeof(struct sys_key), 0600)) < 0){
                exit(1);
        }

        if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
                exit(1);
        }

        return shm;
}
