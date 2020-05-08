#include "nikmak_ecdsa_mpc_poc.h"

#include <string.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

// protocol_ctx_t *protocol_ctx_new()
// {
//   protocol_ctx_t *ctx = malloc(sizeof(protocol_ctx_t));
//   ctx->ec = EC_GROUP_new_by_curve_name(GROUP_ID);

//   ctx->bn_ctx = BN_CTX_new();
  
//   // Set session id (fixed throughout benchmarking)
//   ctx->sid = "Fireblocks - Benchmarking NikMak MPC";

//   return ctx;
// }


// void protocol_ctx_free(protocol_ctx_t *ctx)
// {
//   EC_POINT_free(ctx->H);
//   BN_CTX_free(ctx->bn_ctx);
//   free(ctx);
// }

/**
 *  Fiat-Shamir / Random Oracle
 */

void fiat_shamir_hash(const uint8_t *data, const uint64_t data_len, uint8_t digest[FIAT_SHAMIR_DIGEST_BYTES])
{
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  //SHA256_Update(&sha_ctx, ctx->sid, strlen(ctx->sid));
  SHA256_Update(&sha_ctx, data, data_len);
  SHA256_Final(digest, &sha_ctx);  
}


/** 
 *  Field and Group Elements Basics
 */

scalar_t scalar_new() { return BN_secure_new(); }
void scalar_free(scalar_t el) { BN_clear_free(el); }
ec_group_t ec_group_get() { return EC_GROUP_new_by_curve_name(GROUP_ID); }
gr_elem_t gr_elem_new () { return EC_POINT_new(ec_group_get()); }
void gr_elem_free(gr_elem_t el) { EC_POINT_clear_free(el); }

void sample_in_range(scalar_t rnd, const scalar_t range_mod, int coprime)
{
  BN_rand_range(rnd, range_mod);

  if (coprime)
  { 
    BN_CTX * bn_ctx = BN_CTX_secure_new();
    BIGNUM *gcd = scalar_new();
    BN_gcd(gcd, range_mod, rnd, bn_ctx);
    
    while (!BN_is_one(gcd))
    {
      BN_rand_range(rnd, range_mod);
      BN_gcd(gcd, range_mod, rnd, bn_ctx);
    }
    
    scalar_free(gcd);
    BN_CTX_free(bn_ctx);
  }
}

void sample_safe_prime(unsigned int bits, scalar_t prime)
{
  BN_generate_prime_ex(prime, bits, 1, NULL, NULL, NULL);
}

/**
 *  Paillier Encryption Operations
 */

paillier_private_key_t *paillier_encryption_generate_key ()
{
  paillier_private_key_t *priv = malloc(sizeof(* priv));

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  priv->p       = scalar_new();
  priv->q       = scalar_new();
  priv->mu      = scalar_new();
  priv->lambda  = scalar_new();
  priv->pub.N   = scalar_new();
  priv->pub.N2  = scalar_new();

  sample_safe_prime(PAILLIER_FACTOR_BITS, priv->p);
  sample_safe_prime(PAILLIER_FACTOR_BITS, priv->q);

  BN_mul(priv->pub.N, priv->p, priv->q, bn_ctx);
  BN_sqr(priv->pub.N2, priv->pub.N, bn_ctx);

  BN_sub(priv->lambda, priv->pub.N, priv->p);
  BN_sub(priv->lambda, priv->lambda, priv->q);
  BN_add_word(priv->lambda, 1);

  BN_mod_inverse(priv->mu, priv->lambda, priv->pub.N, bn_ctx);
  
  BN_CTX_free(bn_ctx);

  return priv;
}

paillier_public_key_t *paillier_encryption_copy_public (const paillier_private_key_t *priv)
{
  paillier_public_key_t *pub = malloc(sizeof(*pub));

  pub->N = BN_dup(priv->pub.N);
  pub->N2 = BN_dup(priv->pub.N2);

  return pub;
}

void paillier_encryption_free_keys (paillier_private_key_t *priv, paillier_public_key_t *pub)
{
  if (priv) 
  {
    scalar_free(priv->p);
    scalar_free(priv->q);
    scalar_free(priv->lambda);
    scalar_free(priv->mu);
    scalar_free(priv->pub.N);
    scalar_free(priv->pub.N2);

    free(priv);
  }

  if (pub)
  {
    scalar_free(pub->N);
    scalar_free(pub->N2);

    free(pub);
  }
}


void paillier_encryption_sample(const paillier_public_key_t *pub, scalar_t rho)
{
  sample_in_range(rho, pub->N, 1);
}


void paillier_encryption_encrypt(const paillier_public_key_t *pub, const scalar_t plaintext, const scalar_t rho, scalar_t ciphertext)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new(); 
  BIGNUM *first_factor = scalar_new();
  BIGNUM *res_ciphertext = scalar_new();
  
  BN_mod_mul(first_factor, pub->N, plaintext, pub->N2, bn_ctx);
  BN_add_word(first_factor, 1);
  BN_mod_exp(res_ciphertext, rho, pub->N, pub->N2, bn_ctx);
  BN_mod_mul(res_ciphertext, first_factor, res_ciphertext, pub->N2, bn_ctx);

  BN_copy(ciphertext, res_ciphertext);
  scalar_free(res_ciphertext);
  scalar_free(first_factor);
  BN_CTX_free(bn_ctx);
}


void paillier_encryption_decrypt(const paillier_private_key_t *priv, const scalar_t ciphertext, scalar_t plaintext)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BIGNUM *res_plaintext = scalar_new();

  BN_mod_exp(res_plaintext, ciphertext, priv->lambda, priv->pub.N2, bn_ctx);
  BN_sub_word(res_plaintext, 1);
  BN_div(res_plaintext, NULL, res_plaintext, priv->pub.N, bn_ctx);
  BN_mod_mul(res_plaintext, res_plaintext, priv->mu, priv->pub.N, bn_ctx);

  BN_copy(plaintext, res_plaintext);
  scalar_free(res_plaintext);
  BN_CTX_free(bn_ctx);
}

void paillier_encryption_homomorphic(const paillier_public_key_t *pub, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, scalar_t new_cipher)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BIGNUM *res_new_cipher = BN_dup(ciphertext);

  if (factor) {
    BN_mod_exp(res_new_cipher, res_new_cipher, factor, pub->N2, bn_ctx);
  }
  
  if (add_cipher){
    BN_mod_mul(res_new_cipher, res_new_cipher, add_cipher, pub->N2, bn_ctx);
  }

  BN_copy(new_cipher, res_new_cipher);
  scalar_free(res_new_cipher);
  BN_CTX_free(bn_ctx);
}




ring_pedersen_private_t *ring_pedersen_generate_param  (const scalar_t p, const scalar_t q)
{
  ring_pedersen_private_t *priv = malloc(sizeof(*priv));

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  priv->phi_N = scalar_new();
  priv->lambda = scalar_new();
  priv->pub.N = scalar_new();
  priv->pub.s = scalar_new();
  priv->pub.t = scalar_new();

  BN_mul(priv->pub.N, p, q, bn_ctx);

  BN_sub(priv->phi_N, priv->pub.N, p);
  BN_sub(priv->phi_N, priv->phi_N, q);
  BN_add_word(priv->phi_N, 1);

  sample_in_range(priv->lambda, priv->phi_N, 0);

  BIGNUM *r = scalar_new();
  sample_in_range(r, priv->pub.N, 1);
  BN_mod_mul(priv->pub.t, r, r, priv->pub.N, bn_ctx);
  BN_mod_exp(priv->pub.s, priv->pub.t, priv->lambda, priv->pub.N, bn_ctx);

  scalar_free(r);
  BN_CTX_free(bn_ctx);

  return priv;
}

ring_pedersen_public_t *ring_pedersen_copy_public(const ring_pedersen_private_t *priv)
{
  ring_pedersen_public_t *pub = malloc(sizeof(*pub));

  pub->N = BN_dup(priv->pub.N);
  pub->t = BN_dup(priv->pub.t);
  pub->s = BN_dup(priv->pub.s);

  return pub;
}

void  ring_pedersen_free_param(ring_pedersen_private_t *priv, ring_pedersen_public_t *pub)
{
  if (priv)
  {
    scalar_free(priv->lambda);
    scalar_free(priv->phi_N);
    scalar_free(priv->pub.N);
    scalar_free(priv->pub.s);
    scalar_free(priv->pub.t);

    free(priv);
  }

  if (pub)
  {
    scalar_free(pub->N);
    scalar_free(pub->s);
    scalar_free(pub->t);

    free(pub);
  }
}

void  ring_pedersen_commit(const ring_pedersen_public_t *rped_pub, const scalar_t s_exp, const scalar_t t_exp, scalar_t rped_commitment)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t first_factor = scalar_new();
  scalar_t res_rped_commitment = scalar_new();

  BN_mod_exp(first_factor, rped_pub->s, s_exp, rped_pub->N, bn_ctx);
  BN_mod_exp(res_rped_commitment, rped_pub->t, t_exp, rped_pub->N, bn_ctx);
  BN_mod_mul(res_rped_commitment, first_factor, res_rped_commitment, rped_pub->N, bn_ctx);

  BN_copy(rped_commitment, res_rped_commitment);
  scalar_free(res_rped_commitment);
  scalar_free(first_factor);
  BN_CTX_free(bn_ctx);
}