#include <string.h>
#include <assert.h>
#include <openssl/bn.h>

#ifndef __CMP20_ECDSA_MPC_COMMON_H__
#define __CMP20_ECDSA_MPC_COMMON_H__

void printHexBytes(const char * prefix, const uint8_t *src, unsigned len, const char * suffix);
void printBIGNUM(const char * prefix, const BIGNUM *bn, const char * suffix);

#endif