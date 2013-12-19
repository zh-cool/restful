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

#define KEYFILE         "/etc/keyfile"
#define FILEMODE        (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH)

static int create_keyfile(const uint8_t *key, const uint8_t *iv_enc, const
                uint8_t *iv_dec)
{
        int fd = 0;
        unsigned char md[512];
        if((fd = open(KEYFILE, O_RDWR|O_CREAT|O_TRUNC, FILEMODE)) < 0 ){
                return -1;
        }

        struct sys_key aeskey;
        MD5(key, strlen(key), md);
        memcpy(aeskey.key, md, KEYLEN);

        MD5(iv_enc, strlen((const char*)iv_enc), md);
        memcpy(aeskey.iv_enc, md, AES_BLOCK_SIZE);

        MD5(iv_dec, strlen((const char*)iv_dec), md);
        memcpy(aeskey.iv_dec, md, AES_BLOCK_SIZE);

        write(fd, &aeskey, sizeof(aeskey));
        close(fd);
        return 0;
}

int init_shm()
{
        int fd = 0;
        if(access(KEYFILE, F_OK) < 0){
                if(errno == ENOENT){
                        create_keyfile("111111", "root", "root");
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
