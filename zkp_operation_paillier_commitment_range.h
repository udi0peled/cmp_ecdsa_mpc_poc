#include "zkp_common.h"

#ifndef __CMP20_ECDSA_MPC_ZKP_OPERATION_VS_PAILLIER_H__
#define __CMP20_ECDSA_MPC_ZKP_OPERATION_VS_PAILLIER_H__

#define ZKP_OPERATION_PAILLIER_COMMITMENT_PROOF_BYTES (6*RING_PED_MODULUS_BYTES + 9*PAILLIER_MODULUS_BYTES + 3*CALIGRAPHIC_I_ZKP_RANGE_BYTES + CALIGRAPHIC_J_ZKP_RANGE_BYTES + 4*EPS_ZKP_SLACK_PARAMETER_BYTES)

/** 
 *  Paillier Affine Operation with Paillier Commitment in Range ZKProof 
 */

typedef struct
{
  struct { 
    ring_pedersen_public_t *rped_pub;
    paillier_public_key_t *paillier_pub_0;      // Encrypted the public C
    paillier_public_key_t *paillier_pub_1;      // Encrypted the secret y
    ec_group_t G;
    scalar_t C;       // PAILLIER_MODULUS_BYTES * 2
    scalar_t D;       // PAILLIER_MODULUS_BYTES * 2
    scalar_t Y;       // PAILLIER_MODULUS_BYTES * 2
    scalar_t X;       // PAILLIER_MODULUS_BYTES * 2
  } public;

  struct {
    scalar_t x;       // x_range_bytes
    scalar_t y;       // y_range_bytes
    scalar_t rho;     // PAILLIER_MODULUS_BYTES
    scalar_t rho_x;   // PAILLIER_MODULUS_BYTES
    scalar_t rho_y;   // PAILLIER_MODULUS_BYTES
  } secret;

  struct {
    scalar_t A;       // PAILLIER_MODULUS_BYTES * 2
    scalar_t B_x;     // PAILLIER_MODULUS_BYTES * 2
    scalar_t B_y;     // PAILLIER_MODULUS_BYTES * 2
    scalar_t E;       // RING_PED_MODULUS_BYTES
    scalar_t F;       // RING_PED_MODULUS_BYTES
    scalar_t S;       // RING_PED_MODULUS_BYTES
    scalar_t T;       // RING_PED_MODULUS_BYTES
    scalar_t z_1;     // x_range_bytes + range_slack_bytes
    scalar_t z_2;     // y_range_bytes + range_slack_bytes
    scalar_t z_3;     // RING_PED_MODULUS_BYTES + x_range_bytes + range_slack_bytes
    scalar_t z_4;     // RING_PED_MODULUS_BYTES + x_range_bytes + range_slack_bytes
    scalar_t w;       // PAILLIER_MODULUS_BYTES
    scalar_t w_x;     // PAILLIER_MODULUS_BYTES
    scalar_t w_y;     // PAILLIER_MODULUS_BYTES
  } proof;
} zkp_operation_paillier_commitment_range_t;

// Zero Knowledge Proofs

zkp_operation_paillier_commitment_range_t*
      zkp_operation_paillier_commitment_range_new    ();
void  zkp_operation_paillier_commitment_range_free   (zkp_operation_paillier_commitment_range_t *zkp);
void  zkp_operation_paillier_commitment_range_prove  (zkp_operation_paillier_commitment_range_t *zkp, const zkp_aux_info_t *aux);
int   zkp_operation_paillier_commitment_range_verify (zkp_operation_paillier_commitment_range_t *zkp, const zkp_aux_info_t *aux);

#endif