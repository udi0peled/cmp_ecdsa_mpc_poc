#include "common.h"

void printHexBytes(const char * prefix, const uint8_t *src, unsigned len, const char * suffix)
{
  if (len == 0) {
    printf("%s <0 len char array> %s", prefix, suffix);
    return;
  }

  printf("%s", prefix);
  unsigned int i;
  for (i = 0; i < len-1; ++i) {
    printf("%02x",src[i] & 0xff);
  }
  printf("%02x%s",src[i] & 0xff, suffix);
}

void printBIGNUM(const char * prefix, const BIGNUM *bn, const char * suffix)
{
  char *bn_str = BN_bn2dec(bn);
  printf("%s%s%s", prefix, bn_str, suffix);
  free(bn_str);
}

void printECPOINT(const char * prefix, const EC_POINT *p, const EC_GROUP *ec, const char * suffix, int ignore_compressed_byte)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  uint64_t p_byte_len = EC_POINT_point2oct(ec, p, POINT_CONVERSION_COMPRESSED, NULL, 0, bn_ctx);

  uint8_t *p_bytes = malloc(p_byte_len);
  EC_POINT_point2oct(ec, p, POINT_CONVERSION_COMPRESSED, p_bytes, p_byte_len, bn_ctx);

  if (ignore_compressed_byte) printHexBytes(prefix, p_bytes + 1, p_byte_len - 1, suffix);
  else  printHexBytes(prefix, p_bytes, p_byte_len, suffix);

  free(p_bytes);
  BN_CTX_free(bn_ctx);
}
