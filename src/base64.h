#ifndef _BASE64_H__
#define _BASE64_H_
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

int Base64Decode(char* b64message, uint8_t** buffer, size_t* length);
int Base64Encode(const uint8_t* buffer, size_t length, char** b64text);
#endif
