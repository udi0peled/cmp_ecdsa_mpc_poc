#include "nikmak_ecdsa_mpc_poc.h"

#include <string.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

#define PAILLIER_FACTOR_BYTES (4 * GROUP_ORDER_BYTES)

protocol_ctx_t *protocol_ctx_new()
{
  protocol_ctx_t *gr_ctx = malloc(sizeof(protocol_ctx_t));
  gr_ctx->ec = EC_GROUP_new_by_curve_name(GROUP_ID);

  gr_ctx->bn_ctx = BN_CTX_new();

  //gr_ctx->q = EC_GROUP_get0_order(gr_ctx->ec);
  //gr_ctx->G = EC_GROUP_get0_generator(gr_ctx->ec);

  // Generate H as "nothing up my sleeve", concatenate "Fireblocks" with G's encdoing, and hash to get H.X

  uint8_t point_buffer[GROUP_UNCOMPRESSED_POINT_BYTES + 10] = "Fireblocks";

  EC_POINT_point2oct(gr_ctx->ec, EC_GROUP_get0_generator(gr_ctx->ec), POINT_CONVERSION_UNCOMPRESSED, point_buffer + 10, GROUP_UNCOMPRESSED_POINT_BYTES, NULL);

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
  BN_CTX_free(ctx->bn_ctx);
  free(ctx);
}

scalar_t scalar_new(const protocol_ctx_t *ctx)
{
  return BN_new();
}

void scalar_free(scalar_t el)
{
  BN_clear_free(el);
}

group_el_t group_el_new (const protocol_ctx_t *ctx )
{
  return EC_POINT_new(ctx->ec);
}

void group_el_free(group_el_t el)
{
  EC_POINT_clear_free(el);
}

void sample_in_range(const scalar_t range_mod, scalar_t rnd)
{
  BN_rand_range(rnd, range_mod);
}

void sample_safe_prime(unsigned int bits, scalar_t prime)
{
  BN_generate_prime_ex(prime, bits, 1, NULL, NULL, NULL);
}

void fiat_shamir_hash(const protocol_ctx_t *ctx, const uint8_t *data, const uint64_t data_len, uint8_t digest[FIAT_SHAMIR_DIGEST_BYTES])
{
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, ctx->sid, strlen(ctx->sid));
  SHA256_Update(&sha_ctx, data, data_len);
  SHA256_Final(digest, &sha_ctx);  
}

void group_multiplication(const protocol_ctx_t *ctx, const group_el_t a, const group_el_t b, group_el_t c)
{
  EC_POINT_add(ctx->ec, c, a, b, ctx->bn_ctx);
}

void group_exponentiation(const protocol_ctx_t *ctx, const group_el_t a, const scalar_t exp, group_el_t c)
{
  EC_POINT_mul(ctx->ec, c, NULL, a, exp, ctx->bn_ctx);
}

void group_pedersen_commitment(const protocol_ctx_t *ctx, const scalar_t alpha, const scalar_t beta, group_el_t ped_com)
{
  EC_POINT_mul(ctx->ec, ped_com, alpha, ctx->H, beta, ctx->bn_ctx);
}

// Paillier Encryption
void paillier_encryption_generate_new_keys  (const protocol_ctx_t *ctx, paillier_public_key_t *pub, paillier_private_key_t *priv)
{
  priv->p       = scalar_new(ctx);
  priv->q       = scalar_new(ctx);
  priv->mu      = scalar_new(ctx);
  priv->lambda  = scalar_new(ctx);
  priv->pub.N   = scalar_new(ctx);
  priv->pub.N2  = scalar_new(ctx);

  sample_safe_prime(32*GROUP_ORDER_BYTES, priv->p); // 4 x group order bits
  sample_safe_prime(32*GROUP_ORDER_BYTES, priv->q); // each

  BN_mul(priv->pub.N, priv->p, priv->q, ctx->bn_ctx);
  BN_sqr(priv->pub.N2, priv->pub.N, ctx->bn_ctx);

  pub->N  = BN_dup(priv->pub.N);
  pub->N2 = BN_dup(priv->pub.N2);

  BN_sub(priv->lambda, priv->pub.N, priv->p);
  BN_sub(priv->lambda, priv->lambda, priv->q);
  BN_add_word(priv->lambda, 1);

  BN_mod_inverse(priv->mu, priv->lambda, priv->pub.N, ctx->bn_ctx);
}

void paillier_encryption_free_keys (paillier_public_key_t *pub, paillier_private_key_t *priv)
{
  scalar_free(pub->N);
  scalar_free(pub->N2);

  scalar_free(priv->p);
  scalar_free(priv->q);
  scalar_free(priv->lambda);
  scalar_free(priv->mu);
  scalar_free(priv->pub.N);
  scalar_free(priv->pub.N2);
}