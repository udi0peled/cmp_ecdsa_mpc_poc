#include "paillier_cryptosystem.h"

paillier_private_key_t *paillier_encryption_private_new ()
{
  paillier_private_key_t *priv = malloc(sizeof(*priv));
  
  priv->p     = scalar_new();
  priv->q     = scalar_new();
  priv->mu    = scalar_new();
  priv->phi_N = scalar_new();
  priv->N     = scalar_new();
  priv->N2    = scalar_new(); 

  return priv;
}

void paillier_encryption_private_from_primes (paillier_private_key_t *priv, const scalar_t p, const scalar_t q)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  BN_copy(priv->p, p);
  BN_copy(priv->q, q);

  BN_mul(priv->N, p, q, bn_ctx);
  BN_sqr(priv->N2, priv->N, bn_ctx);

  BN_sub(priv->phi_N, priv->N, p);
  BN_sub(priv->phi_N, priv->phi_N, q);
  BN_add_word(priv->phi_N, 1);

  BN_mod_inverse(priv->mu, priv->phi_N, priv->N, bn_ctx);
  
  BN_CTX_free(bn_ctx);
}

void paillier_encryption_generate_private (paillier_private_key_t *priv, uint64_t prime_bits)
{
  scalar_t p     = scalar_new();
  scalar_t q     = scalar_new();
  scalar_t three = scalar_new();
  scalar_t four  = scalar_new();

  scalar_set_ul(three, 3);
  scalar_set_ul(four, 4);

  BN_generate_prime_ex(p, prime_bits, 0, four, three, NULL);
  BN_generate_prime_ex(q, prime_bits, 0, four, three, NULL);

  paillier_encryption_private_from_primes(priv, p, q);

  scalar_free(p);
  scalar_free(q);
  scalar_free(three);
  scalar_free(four);
}

paillier_public_key_t *paillier_encryption_public_new ()
{
  paillier_public_key_t *pub = malloc(sizeof(paillier_public_key_t));

  pub->N  = scalar_new();
  pub->N2 = scalar_new();
  
  return pub;
}

void paillier_encryption_copy_keys (paillier_private_key_t *copy_priv, paillier_public_key_t *copy_pub, const paillier_private_key_t *priv, const paillier_public_key_t *pub)
{
  if (pub && copy_pub)
  {
    BN_copy(copy_pub->N, pub->N);
    BN_copy(copy_pub->N2, pub->N2);
  }

  if (priv)
  {
    if (copy_priv)
    {
      BN_copy(copy_priv->p, priv->p);
      BN_copy(copy_priv->q, priv->q);
      BN_copy(copy_priv->mu, priv->mu);
      BN_copy(copy_priv->phi_N, priv->phi_N);
      BN_copy(copy_priv->N, priv->N);
      BN_copy(copy_priv->N2, priv->N2);
    }

    if (!pub && copy_pub)
    {
      BN_copy(copy_pub->N, priv->N);
      BN_copy(copy_pub->N2, priv->N2);
    }
  }
}

void paillier_encryption_free_keys (paillier_private_key_t *priv, paillier_public_key_t *pub)
{
  if (priv) 
  {
    scalar_free(priv->p);
    scalar_free(priv->q);
    scalar_free(priv->phi_N);
    scalar_free(priv->mu);
    scalar_free(priv->N);
    scalar_free(priv->N2);

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

  BN_mod_exp(res_plaintext, ciphertext, priv->phi_N, priv->N2, bn_ctx);
  BN_sub_word(res_plaintext, 1);
  BN_div(res_plaintext, NULL, res_plaintext, priv->N, bn_ctx);
  BN_mod_mul(res_plaintext, res_plaintext, priv->mu, priv->N, bn_ctx);

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


void paillier_public_to_bytes (uint8_t **bytes, uint64_t *byte_len, const paillier_public_key_t *pub, uint64_t paillier_modulus_bytes, int move_to_end)
{
  uint64_t needed_byte_len = paillier_modulus_bytes;

  if ((!bytes) || (!*bytes) || (!pub) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }

  uint8_t *set_bytes = *bytes;
  
  scalar_to_bytes(&set_bytes, paillier_modulus_bytes, pub->N, 1);
  
  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void paillier_public_from_bytes (paillier_public_key_t *pub, uint8_t **bytes, uint64_t *byte_len, uint64_t paillier_modulus_bytes, int move_to_end)
{
  uint64_t needed_byte_len = paillier_modulus_bytes;

  if ((!bytes) || (!*bytes) || (!pub) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }

  uint8_t *read_bytes = *bytes;
  
  scalar_from_bytes(pub->N, &read_bytes, paillier_modulus_bytes, 1);
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BN_sqr(pub->N2, pub->N, bn_ctx);
  BN_CTX_free(bn_ctx);
  
  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}