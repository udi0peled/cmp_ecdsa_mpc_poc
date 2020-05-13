#include "zkp_common.h"

#ifndef __CMP20_ECDSA_MPC_ZKP_ENC_IN_RANGE_H__
#define __CMP20_ECDSA_MPC_ZKP_ENC_IN_RANGE_H__

#define ZKP_ENCRYPTION_IN_RANGE_PROOF_BYTES (3*RING_PED_MODULUS_BYTES + 3*PAILLIER_MODULUS_BYTES + 2*ELL_ZKP_RANGE_PARAMETER_BYTES + 2*EPS_ZKP_SLACK_PARAMETER_BYTES)

typedef struct
{
  struct { 
    ring_pedersen_public_t *rped_pub;
    paillier_public_key_t *paillier_pub;
    ec_group_t G;
    scalar_t K;     // PAILLIER_MODULUS_BYTES * 2
  } public;

  struct {
    scalar_t k;     // ELL_ZKP_RANGE_PARAMETER_BYTES
    scalar_t rho;   // PAILLIER_MODULUS_BYTES
  } secret;

  struct {
    scalar_t S;     // RING_PED_MODULUS_BYTES
    scalar_t A;     // PAILLIER_MODULUS_BYTES * 2
    scalar_t C;     // RING_PED_MODULUS_BYTES
    scalar_t z_1;   // ELL_ZKP_RANGE_PARAMETER_BYTES + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t z_2;   // PAILLIER_MODULUS_BYTES
    scalar_t z_3;   // RING_PED_MODULUS_BYTES + ELL_ZKP_RANGE_PARAMETER_BYTES + EPS_ZKP_SLACK_PARAMETER_BYTES
  } proof;
} zkp_encryption_in_range_t;


zkp_encryption_in_range_t *
      zkp_encryption_in_range_new    ();
void  zkp_encryption_in_range_free   (zkp_encryption_in_range_t *zkp);
void  zkp_encryption_in_range_prove  (zkp_encryption_in_range_t *zkp, const zkp_aux_info_t *aux);
int   zkp_encryption_in_range_verify (zkp_encryption_in_range_t *zkp, const zkp_aux_info_t *aux);

#endif