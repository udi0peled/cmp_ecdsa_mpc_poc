#include "common.h"

void printHexBytes(const char * prefix, const uint8_t *src, unsigned len, const char * suffix, int print_len)
{
  if (len == 0) {
    printf("%s <0 len char array> %s", prefix, suffix);
    return;
  }

  if (print_len) printf("[%u]", len);
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

void printECPOINT(const char * prefix, const EC_POINT *p, const EC_GROUP *ec, const char * suffix, int print_uncompressed)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  uint64_t p_byte_len = EC_POINT_point2oct(ec, p, (print_uncompressed ? POINT_CONVERSION_UNCOMPRESSED: POINT_CONVERSION_COMPRESSED), NULL, 0, bn_ctx);
  uint8_t *p_bytes = malloc(p_byte_len);
  EC_POINT_point2oct(ec, p, (print_uncompressed ? POINT_CONVERSION_UNCOMPRESSED: POINT_CONVERSION_COMPRESSED), p_bytes, p_byte_len, bn_ctx);

  if (print_uncompressed)
  {
    printf("%s", prefix);
    printHexBytes("point(0x", p_bytes+1, (p_byte_len-1)/2, ",", 0);
    printHexBytes("0x", p_bytes + (p_byte_len +1)/2, (p_byte_len-1)/2, ")", 0);
    printf("%s", suffix);
  }
  else
  {
    EC_POINT_point2oct(ec, p, POINT_CONVERSION_COMPRESSED, p_bytes, p_byte_len, bn_ctx);
    printHexBytes(prefix, p_bytes, p_byte_len, suffix, 0);
  }
  
  free(p_bytes);
  BN_CTX_free(bn_ctx);
}