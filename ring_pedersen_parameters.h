#include <stdint.h>
#include <openssl/bn.h>

#include "algebraic_elements.h"

#ifndef __CMP20_ECDSA_MPC_RING_PEDERSEN_PARAMS_H__
#define __CMP20_ECDSA_MPC_RING_PEDERSEN_PARAMS_H__

#define RING_PED_MODULUS_BYTES (8*GROUP_ORDER_BYTES)

typedef struct
{
  scalar_t N;
  scalar_t s;
  scalar_t t;
} ring_pedersen_public_t;


typedef struct
{
  ring_pedersen_public_t pub;

  scalar_t lam;
  scalar_t phi_N;
} ring_pedersen_private_t;


ring_pedersen_private_t *
      ring_pedersen_generate_param  (const scalar_t p, const scalar_t q);       // Assumes p,q safe primes (no check)
ring_pedersen_public_t *
      ring_pedersen_copy_public     (const ring_pedersen_private_t *priv);
void  ring_pedersen_free_param      (ring_pedersen_private_t *priv, ring_pedersen_public_t *pub);
void  ring_pedersen_commit          (scalar_t rped_commitment, const scalar_t s_exp, const scalar_t t_exp, const ring_pedersen_public_t *rped_pub);


#endif
