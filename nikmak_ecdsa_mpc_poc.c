#include "nikmak_ecdsa_mpc_poc.h"

#include <string.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#define PAILLIER_FACTOR_BYTES (4 * GROUP_ORDER_BYTES)

struct protocol_ctx 
{
  EC_GROUP *ec;
  BN_CTX *bn_ctx;

  const BIGNUM *q;
  const EC_POINT *G;
  group_el_t H;

  const char* sid;
};

protocol_ctx_t *protocol_ctx_new()
{
  protocol_ctx_t *gr_ctx = malloc(sizeof(protocol_ctx_t));
  gr_ctx->ec = EC_GROUP_new_by_curve_name(GROUP_ID);

  gr_ctx->bn_ctx = BN_CTX_new();

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
  
  // Set session id (fixed throughout benchmarking)
  gr_ctx->sid = "Fireblocks - Benchmarking NikMak MPC";

  return gr_ctx;
}

void protocol_ctx_free(protocol_ctx_t *ctx)
{
  EC_POINT_free(ctx->H);
  EC_GROUP_free(ctx->ec);
  BN_CTX_free(ctx->bn_ctx);
  free(ctx);
}

//void group_multiplication(const group_ctx_t *ctx, EC_POINT * p1, 