#include "nikmak_ecdsa_mpc_poc.h"

#include <string.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

protocol_ctx_t *protocol_ctx_new()
{
  protocol_ctx_t *ctx = malloc(sizeof(protocol_ctx_t));
  ctx->ec = EC_GROUP_new_by_curve_name(GROUP_ID);

  ctx->bn_ctx = BN_CTX_new();
  
  // Set session id (fixed throughout benchmarking)
  ctx->sid = "Fireblocks - Benchmarking NikMak MPC";

  return ctx;
}


void protocol_ctx_free(protocol_ctx_t *ctx)
{
  EC_POINT_free(ctx->H);
  BN_CTX_free(ctx->bn_ctx);
  free(ctx);
}

/**
 *  Fiat-Shamir / Random Oracle
 */

void fiat_shamir_hash(const protocol_ctx_t *ctx, const uint8_t *data, const uint64_t data_len, uint8_t digest[FIAT_SHAMIR_DIGEST_BYTES])
{
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, ctx->sid, strlen(ctx->sid));
  SHA256_Update(&sha_ctx, data, data_len);
  SHA256_Final(digest, &sha_ctx);  
}


/** 
 *  Field and Group Elements Basics
 */

scalar_t scalar_new(const protocol_ctx_t *ctx)
{
  return BN_new();
}

void scalar_free(scalar_t el)
{
  BN_clear_free(el);
}

gr_elem_t gr_elem_new (const protocol_ctx_t *ctx )
{
  return EC_POINT_new(ctx->ec);
}

void gr_elem_free(gr_elem_t el)
{
  EC_POINT_clear_free(el);
}

void sample_in_range(const protocol_ctx_t *ctx, const scalar_t range_mod, scalar_t rnd, int coprime)
{
  BN_rand_range(rnd, range_mod);

  if (coprime)
  { 
    BIGNUM *gcd = BN_new();
    BN_gcd(gcd, range_mod, rnd, ctx->bn_ctx);
    
    while (!BN_is_one(gcd))
    {
      BN_rand_range(rnd, range_mod);
      BN_gcd(gcd, range_mod, rnd, ctx->bn_ctx);
    }
    BN_clear_free(gcd);
  }
}

void sample_safe_prime(unsigned int bits, scalar_t prime)
{
  BN_generate_prime_ex(prime, bits, 1, NULL, NULL, NULL);
}

/**
 *  Paillier Encryption Operations
 */

void paillier_encryption_generate_key (const protocol_ctx_t *ctx, paillier_private_key_t *priv)
{
  priv->p       = BN_new();
  priv->q       = BN_new();;
  priv->mu      = BN_new();;
  priv->lambda  = BN_new();;
  priv->pub.N   = BN_new();;
  priv->pub.N2  = BN_new();;

  sample_safe_prime(PAILLIER_FACTOR_BITS, priv->p);
  sample_safe_prime(PAILLIER_FACTOR_BITS, priv->q);

  BN_mul(priv->pub.N, priv->p, priv->q, ctx->bn_ctx);
  BN_sqr(priv->pub.N2, priv->pub.N, ctx->bn_ctx);

  BN_sub(priv->lambda, priv->pub.N, priv->p);
  BN_sub(priv->lambda, priv->lambda, priv->q);
  BN_add_word(priv->lambda, 1);

  BN_mod_inverse(priv->mu, priv->lambda, priv->pub.N, ctx->bn_ctx);
}


void paillier_encryption_free_keys (const paillier_private_key_t *priv, const paillier_public_key_t *pub)
{
  if (priv) 
  {
    BN_free(priv->p);
    BN_free(priv->q);
    BN_free(priv->lambda);
    BN_free(priv->mu);
    BN_free(priv->pub.N);
    BN_free(priv->pub.N2);
  }

  if (pub)
  {
    BN_free(pub->N);
    BN_free(pub->N2);
  }
}


void paillier_encryption_sample(const protocol_ctx_t *ctx, const paillier_public_key_t *pub, scalar_t rho)
{
  sample_in_range(ctx, pub->N, rho, 1);
}


void paillier_encryption_encrypt(const protocol_ctx_t *ctx, const paillier_public_key_t *pub, const scalar_t plaintext, const scalar_t rho, scalar_t ciphertext)
{
  BIGNUM *first_factor = BN_new();
  BIGNUM *res_ciphertext = BN_new();
  
  BN_mod_mul(first_factor, pub->N, plaintext, pub->N2, ctx->bn_ctx);
  BN_add_word(first_factor, 1);

  BN_mod_exp(res_ciphertext, rho, pub->N, pub->N2, ctx->bn_ctx);
  BN_mod_mul(res_ciphertext, first_factor, res_ciphertext, pub->N2, ctx->bn_ctx);

  BN_copy(ciphertext, res_ciphertext);
  BN_clear_free(res_ciphertext);
  BN_clear_free(first_factor);
}


void paillier_encryption_decrypt(const protocol_ctx_t *ctx, const paillier_private_key_t *priv, const scalar_t ciphertext, scalar_t plaintext)
{
  BIGNUM *res_plaintext = BN_new();

  BN_mod_exp(res_plaintext, ciphertext, priv->lambda, priv->pub.N2, ctx->bn_ctx);
  BN_sub_word(res_plaintext, 1);
  BN_div(res_plaintext, NULL, res_plaintext, priv->pub.N, ctx->bn_ctx);
  BN_mod_mul(res_plaintext, res_plaintext, priv->mu, priv->pub.N, ctx->bn_ctx);

  BN_copy(plaintext, res_plaintext);
  BN_clear_free(res_plaintext);
}

void paillier_encryption_homomorphic(const protocol_ctx_t *ctx, const paillier_public_key_t *pub, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, scalar_t new_cipher)
{
  BIGNUM *res_new_cipher = BN_dup(ciphertext);

  if (factor) {
    BN_mod_exp(res_new_cipher, res_new_cipher, factor, pub->N2, ctx->bn_ctx);
  }
  
  if (add_cipher){
    BN_mod_mul(res_new_cipher, res_new_cipher, add_cipher, pub->N2, ctx->bn_ctx);
  }

  BN_copy(new_cipher, res_new_cipher);

  BN_clear_free(res_new_cipher);
}
