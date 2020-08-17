/**
 * 
 *  Name:
 *  ring_pedersen_parameters
 *  
 *  Description:
 *  Basic ring pedersen parameters and commitment generation.
 * 
 *  Usage:
 *  Generate private key from given two prime (computed N and sample random s,t,lam as required), from which also public key can be extracted.
 *  Compute ring pedersen commitments.
 * 
 */

#ifndef __CMP20_ECDSA_MPC_RING_PEDERSEN_PARAMS_H__
#define __CMP20_ECDSA_MPC_RING_PEDERSEN_PARAMS_H__

#include <stdint.h>
#include <openssl/bn.h>

#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"

typedef struct
{
  scalar_t N;
  scalar_t s;
  scalar_t t;
} ring_pedersen_public_t;


typedef struct
{
  // Public
  scalar_t N;
  scalar_t s;
  scalar_t t;

  // Private 
  scalar_t lam;
  scalar_t phi_N;
} ring_pedersen_private_t;


ring_pedersen_private_t *
      ring_pedersen_private_new         ();
ring_pedersen_public_t *  
      ring_pedersen_public_new          ();
void  ring_pedersen_private_from_primes (ring_pedersen_private_t *priv, const scalar_t p, const scalar_t q);
void  ring_pedersen_generate_private    (ring_pedersen_private_t *priv, uint64_t prime_bits);
void  ring_pedersen_copy_param          (ring_pedersen_private_t *copy_priv, ring_pedersen_public_t *copy_pub, const ring_pedersen_private_t *priv, const ring_pedersen_public_t *pub);
// Free keys, each can be NULL and ignored. Public inside private is freed with private, shouldn't be freeed seperately
void  ring_pedersen_free_param          (ring_pedersen_private_t *priv, ring_pedersen_public_t *pub);
void  ring_pedersen_commit              (scalar_t rped_commitment, const scalar_t s_exp, const scalar_t t_exp, const ring_pedersen_public_t *rped_pub);
void  ring_pedersen_public_to_bytes     (uint8_t **bytes, uint64_t *byte_len, const ring_pedersen_public_t *rped_pub, uint64_t rped_modulus_bytes, int move_to_end);
void  ring_pedersen_public_from_bytes   (ring_pedersen_public_t *rped_pub, uint8_t **bytes, uint64_t *byte_len, uint64_t rped_modulus_bytes, int move_to_end);

#endif
