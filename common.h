/**
 * 
 *  Name:
 *  common
 *  
 *  Description:
 *  Common printing function for bytes, bignums and ec points.
 * 
 */

#ifndef __CMP20_ECDSA_MPC_COMMON_H__
#define __CMP20_ECDSA_MPC_COMMON_H__

#include <string.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

void printHexBytes(const char * prefix, const uint8_t *src, unsigned len, const char * suffix, int print_len);
void printBIGNUM(const char * prefix, const BIGNUM *bn, const char * suffix);
void printECPOINT(const char * prefix, const EC_POINT *p, const EC_GROUP *ec, const char * suffix, int print_uncompressed);

#endif