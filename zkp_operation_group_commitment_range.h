#include "zkp_common.h"

#ifndef __CMP20_ECDSA_MPC_ZKP_OPERATION_VS_GROUP_H__
#define __CMP20_ECDSA_MPC_ZKP_OPERATION_VS_GROUP_H__

#define ZKP_OPERATION_VS_GROUP_PROOF_BYTES (GROUP_ELEMENT_BYTES + 6*RING_PED_MODULUS_BYTES + 6*PAILLIER_MODULUS_BYTES + 3*CALIGRAPHIC_I_ZKP_RANGE_BYTES + CALIGRAPHIC_J_ZKP_RANGE_BYTES + 4*EPS_ZKP_SLACK_PARAMETER_BYTES)

typedef struct
{
  struct { 
    ring_pedersen_public_t *rped_pub;
    paillier_public_key_t *paillier_pub_0;    // Encrypted public C
    paillier_public_key_t *paillier_pub_1;    // Encrypted secret y
    ec_group_t G;
    gr_elem_t g;      // GROUP_ELEMENT_BYTES
    scalar_t C;       // PAILLIER_MODULUS_BYTES * 2
    scalar_t D;       // PAILLIER_MODULUS_BYTES * 2
    scalar_t Y;       // PAILLIER_MODULUS_BYTES * 2
    gr_elem_t X;      // GROUP_ELEMENT_BYTES
  } public;


  struct {
    scalar_t x;       // CALIGRAPHIC_I_ZKP_RANGE_BYTES
    scalar_t y;       // CALIGRAPHIC_J_ZKP_RANGE_BYTES
    scalar_t rho;     // PAILLIER_MODULUS_BYTES
    scalar_t rho_y;   // PAILLIER_MODULUS_BYTES
  } secret;

  struct {
    scalar_t A;       // PAILLIER_MODULUS_BYTES * 2
    gr_elem_t B_x;    // GROUP_ELEMENT_BYTES
    scalar_t B_y;     // PAILLIER_MODULUS_BYTES * 2
    scalar_t E;       // RING_PED_MODULUS_BYTES
    scalar_t F;       // RING_PED_MODULUS_BYTES
    scalar_t S;       // RING_PED_MODULUS_BYTES
    scalar_t T;       // RING_PED_MODULUS_BYTES
    scalar_t z_1;     // CALIGRAPHIC_I_ZKP_RANGE_BYTES + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t z_2;     // CALIGRAPHIC_J_ZKP_RANGE_BYTES + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t z_3;     // RING_PED_MODULUS_BYTES + CALIGRAPHIC_I_ZKP_RANGE_BYTES + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t z_4;     // RING_PED_MODULUS_BYTES + CALIGRAPHIC_I_ZKP_RANGE_BYTES + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t w;       // PAILLIER_MODULUS_BYTES
    scalar_t w_y;     // PAILLIER_MODULUS_BYTES
  } proof;
} zkp_operation_group_commitment_range_t;

zkp_operation_group_commitment_range_t *
      zkp_operation_group_commitment_range_new    ();
void  zkp_operation_group_commitment_range_free   (zkp_operation_group_commitment_range_t *zkp);
void  zkp_operation_group_commitment_range_prove  (zkp_operation_group_commitment_range_t *zkp, const zkp_aux_info_t *aux);
int   zkp_operation_group_commitment_range_verify (zkp_operation_group_commitment_range_t *zkp, const zkp_aux_info_t *aux);

#endif