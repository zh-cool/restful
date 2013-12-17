#include "base64.h"
static size_t calcDecodeLength(const char* b64input)
{
        size_t len = strlen(b64input), padding = 0;

        if (b64input[len-1] == '=' && b64input[len-2] == '=')
                padding = 2;
        else if (b64input[len-1] == '=')
                padding = 1;
        return (size_t)len*0.75 - padding;
}

int Base64Decode(char* b64message, uint8_t** buffer, size_t* length)
{
        BIO *bio, *b64;

        int decodeLen = calcDecodeLength(b64message);
        *buffer = (uint8_t*)malloc(decodeLen);

        bio = BIO_new_mem_buf(b64message, -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        *length = BIO_read(bio, *buffer, strlen(b64message));
        assert(*length == decodeLen);
        BIO_free_all(bio);

        return (0);
}

int Base64Encode(const uint8_t* buffer, size_t length, char** b64text)
{
        BIO *bio, *b64;
        BUF_MEM *bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        bio = BIO_new(BIO_s_mem());
        bio = BIO_push(b64, bio);

        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        BIO_write(bio, buffer, length);
        BIO_flush(bio);
        BIO_get_mem_ptr(bio, &bufferPtr);
        BIO_set_close(bio, BIO_NOCLOSE);
        BIO_free_all(bio);

        *b64text=(*bufferPtr).data;

        return (0);
}
