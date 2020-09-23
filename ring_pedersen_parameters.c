#include "ring_pedersen_parameters.h"
#include <assert.h>

ring_pedersen_private_t *ring_pedersen_private_new ()
{
  ring_pedersen_private_t *priv = malloc(sizeof(ring_pedersen_private_t));

  priv->phi_N = scalar_new();
  priv->lam   = scalar_new();
  priv->N = scalar_new();
  priv->s = scalar_new();
  priv->t = scalar_new();

  return priv;
}

void ring_pedersen_private_from_primes  (ring_pedersen_private_t *priv, const scalar_t p, const scalar_t q)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  BN_mul(priv->N, p, q, bn_ctx);

  BN_sub(priv->phi_N, priv->N, p);
  BN_sub(priv->phi_N, priv->phi_N, q);
  BN_add_word(priv->phi_N, 1);

  scalar_sample_in_range(priv->lam, priv->phi_N, 0);

  scalar_t r = scalar_new();
  scalar_sample_in_range(r, priv->N, 1);
  BN_mod_mul(priv->t, r, r, priv->N, bn_ctx);
  BN_mod_exp(priv->s, priv->t, priv->lam, priv->N, bn_ctx);
  scalar_free(r);
  
  BN_CTX_free(bn_ctx);
}

void ring_pedersen_generate_private (ring_pedersen_private_t *priv, uint64_t prime_bits) 
{ 
  scalar_t p = scalar_new();
  scalar_t q = scalar_new();

  BN_generate_prime_ex(p, prime_bits, 1, NULL, NULL, NULL);
  BN_generate_prime_ex(q, prime_bits, 1, NULL, NULL, NULL);

  ring_pedersen_private_from_primes(priv, p, q);

  scalar_free(p);
  scalar_free(q);
}

ring_pedersen_public_t  *ring_pedersen_public_new()
{
  ring_pedersen_public_t *pub = malloc(sizeof(ring_pedersen_public_t));
  
  pub->N = scalar_new();
  pub->s = scalar_new();
  pub->t = scalar_new();

  return pub;
}
void ring_pedersen_copy_param (ring_pedersen_private_t *copy_priv, ring_pedersen_public_t *copy_pub, const ring_pedersen_private_t *priv, const ring_pedersen_public_t *pub)
{
  if (pub && copy_pub)
  {
    BN_copy(copy_pub->N, pub->N);
    BN_copy(copy_pub->s, pub->s);
    BN_copy(copy_pub->t, pub->t);
  }

  if (priv)
  {
    if (copy_priv)
    {
      BN_copy(copy_priv->N, priv->N);
      BN_copy(copy_priv->s, priv->s);
      BN_copy(copy_priv->t, priv->t);
      BN_copy(copy_priv->lam, priv->lam);
      BN_copy(copy_priv->phi_N, priv->phi_N);
    }

    if (!pub && copy_pub)
    {
      BN_copy(copy_pub->N, priv->N);
      BN_copy(copy_pub->s, priv->s);
      BN_copy(copy_pub->t, priv->t);
    }
  }
}

void  ring_pedersen_free_param(ring_pedersen_private_t *priv, ring_pedersen_public_t *pub)
{
  if (priv)
  {
    scalar_free(priv->lam);
    scalar_free(priv->phi_N);
    scalar_free(priv->N);
    scalar_free(priv->s);
    scalar_free(priv->t);

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

void  ring_pedersen_commit(scalar_t rped_commitment, const scalar_t s_exp, const scalar_t t_exp, const ring_pedersen_public_t *rped_pub)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t first_factor = scalar_new();
  scalar_t res_rped_commitment = scalar_new();

  BN_mod_exp(first_factor, rped_pub->s, s_exp, rped_pub->N, bn_ctx);
  if (BN_is_negative(s_exp)) BN_mod_inverse(first_factor, first_factor, rped_pub->N, bn_ctx);
  BN_mod_exp(res_rped_commitment, rped_pub->t, t_exp, rped_pub->N, bn_ctx);
  if (BN_is_negative(t_exp)) BN_mod_inverse(res_rped_commitment, res_rped_commitment, rped_pub->N, bn_ctx);
  BN_mod_mul(res_rped_commitment, first_factor, res_rped_commitment, rped_pub->N, bn_ctx);

  BN_copy(rped_commitment, res_rped_commitment);
  scalar_free(res_rped_commitment);
  scalar_free(first_factor);
  BN_CTX_free(bn_ctx);
}

void ring_pedersen_public_to_bytes (uint8_t **bytes, uint64_t *byte_len, const ring_pedersen_public_t *rped_pub, uint64_t rped_modulus_bytes, int move_to_end)
{
  uint64_t needed_byte_len = 3*rped_modulus_bytes;

  if ((!bytes) || (!*bytes) || (!rped_pub) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }

  uint8_t *set_bytes = *bytes;
  
  scalar_to_bytes(&set_bytes, rped_modulus_bytes, rped_pub->N, 1);
  scalar_to_bytes(&set_bytes, rped_modulus_bytes, rped_pub->s, 1);
  scalar_to_bytes(&set_bytes, rped_modulus_bytes, rped_pub->t, 1);

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void ring_pedersen_public_from_bytes (ring_pedersen_public_t *rped_pub, uint8_t **bytes, uint64_t *byte_len, uint64_t rped_modulus_bytes, int move_to_end)
{
  uint64_t needed_byte_len = 3*rped_modulus_bytes;

  if ((!bytes) || (!*bytes) || (!rped_pub) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }

  uint8_t *read_bytes = *bytes;
  
  scalar_from_bytes(rped_pub->N, &read_bytes, rped_modulus_bytes, 1);
  scalar_coprime_from_bytes(rped_pub->s, &read_bytes, rped_modulus_bytes, rped_pub->N, 1);
  scalar_coprime_from_bytes(rped_pub->t, &read_bytes, rped_modulus_bytes, rped_pub->N, 1);

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}