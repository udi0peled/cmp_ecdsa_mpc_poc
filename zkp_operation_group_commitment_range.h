/**
 * 
 *  Name:
 *  zkp_operation_group_commitment_range
 *  
 *  Description:
 *  Paillier Homomorphic Operation against Paillier Ciphertext with Plaintext in Range Zero Knoeledge Proof.
 * 
 *  Usage:
 *  Constructor and destructor for zkp_<...>_t don't set any values and handles only proof fields.
 *  When using <...>_prove, all public and secret fields of zkp_<...>_t needs to be already populated (externally).
 *  Calling <...>_prove sets only the proof fields.
 *  When using <...>_verify, all public and proof fields of zkp_<...>_t need to be already populated.
 *  Calling <...>_verify return 0/1 (fail/pass).
 * 
 */

#ifndef __CMP20_ECDSA_MPC_ZKP_OPERATION_VS_GROUP_H__
#define __CMP20_ECDSA_MPC_ZKP_OPERATION_VS_GROUP_H__

#include "zkp_common.h"

typedef struct
{
  struct { 
    uint64_t x_range_bytes;
    uint64_t y_range_bytes;
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
    scalar_t x;       // x_range_bytes
    scalar_t y;       // y_range_bytes
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
    scalar_t z_1;     // x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t z_2;     // y_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t z_3;     // RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t z_4;     // RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t w;       // PAILLIER_MODULUS_BYTES
    scalar_t w_y;     // PAILLIER_MODULUS_BYTES
  } proof;
} zkp_operation_group_commitment_range_t;

zkp_operation_group_commitment_range_t *
     zkp_operation_group_commitment_range_new            ();
void zkp_operation_group_commitment_range_free           (zkp_operation_group_commitment_range_t *zkp);
void zkp_operation_group_commitment_range_prove          (zkp_operation_group_commitment_range_t *zkp, const zkp_aux_info_t *aux);
int  zkp_operation_group_commitment_range_verify         (zkp_operation_group_commitment_range_t *zkp, const zkp_aux_info_t *aux);
void zkp_operation_group_commitment_range_proof_to_bytes (uint8_t **bytes, uint64_t *byte_len, const zkp_operation_group_commitment_range_t *zkp, uint64_t x_range_bytes, uint64_t y_range_bytes, int move_to_end);

#endif