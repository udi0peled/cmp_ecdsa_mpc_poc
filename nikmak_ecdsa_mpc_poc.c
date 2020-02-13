#include "nikmak_ecdsa_mpc_poc.h"

#include <string.h>
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#define PAILLIER_FACTOR_BYTES (4 * GROUP_ORDER_BYTES)

typedef EC_POINT *group_element;
typedef BIGNUM *scalar;

struct group_ctx 
{
  EC_GROUP *ec;
  const BIGNUM *q;
  const EC_POINT *G;
  EC_POINT *H;
};

struct paillier_public_key
{
  uint8_t N[2*PAILLIER_FACTOR_BYTES];
  uint8_t N2[4*PAILLIER_FACTOR_BYTES];
};

struct paillier_private_key
{
  struct paillier_public_key pub;
  uint8_t p[PAILLIER_FACTOR_BYTES];
  uint8_t q[PAILLIER_FACTOR_BYTES];
  uint8_t lcm[PAILLIER_FACTOR_BYTES];    // exponent in decryption
  uint8_t mu[2*PAILLIER_FACTOR_BYTES];   // multiplicative factor in decryption
};

group_ctx_t *group_ctx_new()
{
  group_ctx_t *gr_ctx = malloc(sizeof(group_ctx_t));
  gr_ctx->ec = EC_GROUP_new_by_curve_name(GROUP_ID);
  gr_ctx->q = EC_GROUP_get0_order(gr_ctx->ec);
  gr_ctx->G = EC_GROUP_get0_generator(gr_ctx->ec);

  // Generate H as "nothing up my sleeve", concatenate "Fireblocks" with G's encdoing, and hash to get H.X

  uint8_t point_buffer[GROUP_UNCOMPRESSED_POINT_BYTES + 10] = "Fireblocks";

  EC_POINT_point2oct(gr_ctx->ec, gr_ctx->G, POINT_CONVERSION_UNCOMPRESSED, point_buffer + 10, GROUP_UNCOMPRESSED_POINT_BYTES, NULL);

  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, point_buffer, sizeof(point_buffer));
  SHA256_Final(point_buffer + 1, &sha_ctx);  

  // Decompress H.X to point H
  point_buffer[0] = 0x02;

  gr_ctx->H = EC_POINT_new(gr_ctx->ec);
  assert(EC_POINT_oct2point(gr_ctx->ec, gr_ctx->H, point_buffer, GROUP_COMPRESSED_POINT_BYTES, NULL) == 1);
  
  return gr_ctx;
}

void group_ctx_free(group_ctx_t *ctx)
{
  EC_POINT_free(ctx->H);
  EC_GROUP_free(ctx->ec);
  free(ctx);
}

//void group_multiplication(const group_ctx_t *ctx, EC_POINT * p1, 