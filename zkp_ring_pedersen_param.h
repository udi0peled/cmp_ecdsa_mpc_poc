/**
 * 
 *  Name:
 *  zkp_ring_pedersen_param
 *  
 *  Description:
 *  Paillier Blum Modulus Zero Knowledge Proof for modulus of RING_PED_MODULUS_BYTES byte length (hardcoded in verification).
 * 
 *  Usage:
 *  Constructor and destructor for zkp_<...>_t don't set any values and handles only proof fields.
 *  When using <...>_prove, all public and secret fields of zkp_<...>_t needs to be already populated (externally).
 *  Calling <...>_prove sets only the proof fields.
 *  When using <...>_verify, all public and proof fields of zkp_<...>_t need to be already populated.
 *  Calling <...>_verify return 0/1 (fail/pass).
 * 
 */

#ifndef __CMP20_ECDSA_MPC_ZKP_RING_PEDERSEN_H__
#define __CMP20_ECDSA_MPC_ZKP_RING_PEDERSEN_H__

#include "zkp_common.h"

/**
 *  Ring Pedersend Parameters ZKProof
 */

typedef struct
{
  scalar_t A[STATISTICAL_SECURITY];
  scalar_t z[STATISTICAL_SECURITY];

} zkp_ring_pedersen_param_proof_t;

zkp_ring_pedersen_param_proof_t *
     zkp_ring_pedersen_param_new              ();
void zkp_ring_pedersen_param_free             (zkp_ring_pedersen_param_proof_t *proof);
void zkp_ring_pedersen_param_prove            (zkp_ring_pedersen_param_proof_t *proof, const ring_pedersen_private_t *private, const zkp_aux_info_t *aux);
int  zkp_ring_pedersen_param_verify           (const zkp_ring_pedersen_param_proof_t *proof, const ring_pedersen_public_t *public, const zkp_aux_info_t *aux);
void zkp_ring_pedersen_param_proof_to_bytes   (uint8_t **bytes, uint64_t *byte_len, const zkp_ring_pedersen_param_proof_t *proof, int move_to_end);
void zkp_ring_pedersen_param_proof_from_bytes (zkp_ring_pedersen_param_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, int move_to_end);

#endif