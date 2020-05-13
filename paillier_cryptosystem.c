#include "paillier_cryptosystem.h"

paillier_private_key_t *paillier_encryption_generate_key ()
{
  paillier_private_key_t *priv = malloc(sizeof(*priv));

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  priv->p       = scalar_new();
  priv->q       = scalar_new();
  priv->mu      = scalar_new();
  priv->lambda  = scalar_new();
  priv->pub.N   = scalar_new();
  priv->pub.N2  = scalar_new();

  sample_safe_prime(priv->p, 4*PAILLIER_MODULUS_BYTES);
  sample_safe_prime(priv->q, 4*PAILLIER_MODULUS_BYTES);

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


void paillier_encryption_sample (scalar_t rho, const paillier_public_key_t *pub)
{
  scalar_sample_in_range(rho, pub->N, 1);
}


void paillier_encryption_encrypt (scalar_t ciphertext, const scalar_t plaintext, const scalar_t rho, const paillier_public_key_t *pub)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new(); 
  BIGNUM *first_factor = scalar_new();
  BIGNUM *res_ciphertext = scalar_new();
  
  BN_mod_mul(first_factor, pub->N, plaintext, pub->N2, bn_ctx);
  BN_add_word(first_factor, 1);
  scalar_exp(res_ciphertext, rho, pub->N, pub->N2);
  BN_mod_mul(res_ciphertext, first_factor, res_ciphertext, pub->N2, bn_ctx);

  BN_copy(ciphertext, res_ciphertext);
  scalar_free(res_ciphertext);
  scalar_free(first_factor);
  BN_CTX_free(bn_ctx);
}


void paillier_encryption_decrypt (scalar_t plaintext, const scalar_t ciphertext, const paillier_private_key_t *priv)
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

void paillier_encryption_homomorphic (scalar_t new_cipher, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, const paillier_public_key_t *pub)
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
