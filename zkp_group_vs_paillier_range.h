#include "zkp_common.h"

#ifndef __CMP20_ECDSA_MPC_ZKP_GROUP_VS_PAILLIER_H__
#define __CMP20_ECDSA_MPC_ZKP_GROUP_VS_PAILLIER_H__

#define ZKP_GROUP_VS_PAILLIER_PROOF_BYTES (GROUP_ELEMENT_BYTES + 3*RING_PED_MODULUS_BYTES + 3*PAILLIER_MODULUS_BYTES + 2*CALIGRAPHIC_I_ZKP_RANGE_BYTES + 2*EPS_ZKP_SLACK_PARAMETER_BYTES)

/** 
 *  Group Element vs Paillier Paillier Encryption in Range ZKProof 
 */

typedef struct
{
  struct { 
    ring_pedersen_public_t *rped_pub;
    paillier_public_key_t *paillier_pub;
    ec_group_t G;
    gr_elem_t g;    // GROUP_ELEMENT_BYTES
    scalar_t C;     // PAILLIER_MODULUS_BYTES * 2
    gr_elem_t X;    // GROUP_ELEMENT_BYTES
  } public;

  struct {
    scalar_t x;     // CALIGRAPHIC_I_ZKP_RANGE_BYTES + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t rho;   // PAILLIER_MODULUS_BYTES
  } secret;

  struct {
    scalar_t S;     // RING_PED_MODULUS_BYTES
    scalar_t A;     // PAILLIER_MODULUS_BYTES * 2
    gr_elem_t Y;    // GROUP_ELEMENT_BYTES
    scalar_t D;     // RING_PED_MODULUS_BYTES
    scalar_t z_1;   // CALIGRAPHIC_I_ZKP_RANGE_BYTES + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t z_2;   // PAILLIER_MODULUS_BYTES
    scalar_t z_3;   // RING_PED_MODULUS_BYTES + CALIGRAPHIC_I_ZKP_RANGE_BYTES + EPS_ZKP_SLACK_PARAMETER_BYTES
  } proof;
} zkp_group_vs_paillier_range_t;

zkp_group_vs_paillier_range_t *
         zkp_group_vs_paillier_range_new         ();
void     zkp_group_vs_paillier_range_free        (zkp_group_vs_paillier_range_t *zkp);
void     zkp_group_vs_paillier_range_prove       (zkp_group_vs_paillier_range_t *zkp, const zkp_aux_info_t *aux);
int      zkp_group_vs_paillier_range_verify      (zkp_group_vs_paillier_range_t *zkp, const zkp_aux_info_t *aux);

#endif