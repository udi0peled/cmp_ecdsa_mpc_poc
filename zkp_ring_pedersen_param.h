#include "algebraic_elements.h"

#include "ring_pedersen_parameters.h"
#include "zkp_common.h"

#ifndef __CMP20_ECDSA_MPC_ZKP_RING_PEDERSEN_H__
#define __CMP20_ECDSA_MPC_ZKP_RING_PEDERSEN_H__

#define ZKP_RING_PEDERSEN_PARAM_PROOF_BYTES (2*RING_PED_MODULUS_BYTES*STATISTICAL_SECURITY)

/**
 *  Ring Pedersend Parameters ZKProof
 */

typedef struct
{
  ring_pedersen_public_t *rped_pub;

  struct {
    scalar_t lambda;
  } secret;

  struct {
    scalar_t A[STATISTICAL_SECURITY];
    scalar_t z[STATISTICAL_SECURITY];
  } proof;
} zkp_ring_pedersen_param_t;

zkp_ring_pedersen_param_t *
      zkp_ring_pedersen_param_new    ();
void  zkp_ring_pedersen_param_free   (zkp_ring_pedersen_param_t *zkp);
void  zkp_ring_pedersen_param_prove  (zkp_ring_pedersen_param_t *zkp, const zkp_aux_info_t *aux);
int   zkp_ring_pedersen_param_verify (zkp_ring_pedersen_param_t *zkp, const zkp_aux_info_t *aux);

#endif