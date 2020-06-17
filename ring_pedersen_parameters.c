#include "ring_pedersen_parameters.h"
#include <assert.h>

ring_pedersen_private_t *ring_pedersen_generate_param  (const scalar_t p, const scalar_t q)
{
  ring_pedersen_private_t *priv = malloc(sizeof(*priv));

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  priv->phi_N = scalar_new();
  priv->lam   = scalar_new();
  priv->pub.N = scalar_new();
  priv->pub.s = scalar_new();
  priv->pub.t = scalar_new();

  BN_mul(priv->pub.N, p, q, bn_ctx);

  BN_sub(priv->phi_N, priv->pub.N, p);
  BN_sub(priv->phi_N, priv->phi_N, q);
  BN_add_word(priv->phi_N, 1);

  scalar_sample_in_range(priv->lam, priv->phi_N, 0);

  scalar_t r = scalar_new();
  scalar_sample_in_range(r, priv->pub.N, 1);
  BN_mod_mul(priv->pub.t, r, r, priv->pub.N, bn_ctx);
  BN_mod_exp(priv->pub.s, priv->pub.t, priv->lam, priv->pub.N, bn_ctx);
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
    scalar_free(priv->lam);
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
