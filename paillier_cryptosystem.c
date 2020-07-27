#include "paillier_cryptosystem.h"

paillier_private_key_t *paillier_encryption_key_from_primes (const scalar_t p, const scalar_t q)
{
  paillier_private_key_t *priv = malloc(sizeof(*priv));

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  priv->p = BN_dup(p);
  priv->q = BN_dup(q);
  
  priv->mu      = scalar_new();
  priv->phi_N   = scalar_new();
  priv->pub.N   = scalar_new();
  priv->pub.N2  = scalar_new();

  BN_mul(priv->pub.N, p, q, bn_ctx);
  BN_sqr(priv->pub.N2, priv->pub.N, bn_ctx);

  BN_sub(priv->phi_N, priv->pub.N, p);
  BN_sub(priv->phi_N, priv->phi_N, q);
  BN_add_word(priv->phi_N, 1);

  BN_mod_inverse(priv->mu, priv->phi_N, priv->pub.N, bn_ctx);
  
  BN_CTX_free(bn_ctx);

  return priv;
}


paillier_private_key_t *paillier_encryption_generate_key (uint64_t prime_bits)
{
  scalar_t p     = scalar_new();
  scalar_t q     = scalar_new();
  scalar_t three = scalar_new();
  scalar_t four  = scalar_new();

  scalar_set_ul(three, 3);
  scalar_set_ul(four, 4);

  BN_generate_prime_ex(p, prime_bits, 0, four, three, NULL);
  BN_generate_prime_ex(q, prime_bits, 0, four, three, NULL);

  paillier_private_key_t *priv = paillier_encryption_key_from_primes (p, q);

  scalar_free(p);
  scalar_free(q);
  return priv;
}

paillier_private_key_t *paillier_encryption_duplicate_key (const paillier_private_key_t *priv)
{
  paillier_private_key_t *copy = malloc(sizeof(*copy));

  copy->p      = BN_dup(priv->p);
  copy->q      = BN_dup(priv->q);
  copy->mu     = BN_dup(priv->mu);
  copy->phi_N  = BN_dup(priv->phi_N);
  copy->pub.N  = BN_dup(priv->pub.N);
  copy->pub.N2 = BN_dup(priv->pub.N2);

  return copy;
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
    scalar_free(priv->phi_N);
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

  BN_mod_exp(res_plaintext, ciphertext, priv->phi_N, priv->pub.N2, bn_ctx);
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

  if (factor)
  {
    // If exp negative, it ignores and uses positive, and invert result (fail if result isn't coprime to modulus)
    BN_mod_exp(res_new_cipher, res_new_cipher, factor, pub->N2, bn_ctx);
    if (BN_is_negative(factor)) BN_mod_inverse(res_new_cipher, res_new_cipher, pub->N2, bn_ctx);
  }
  
  if (add_cipher)
  {
    BN_mod_mul(res_new_cipher, res_new_cipher, add_cipher, pub->N2, bn_ctx);
  }

  BN_copy(new_cipher, res_new_cipher);
  scalar_free(res_new_cipher);
  BN_CTX_free(bn_ctx);
}
