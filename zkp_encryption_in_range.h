/**
 * 
 *  Name:
 *  zkp_encryption_in_range
 *  
 *  Description:
 *  Paillier Encryption in Range Zero Knowledge Proof.
 * 
 *  Usage:
 *  Constructor and destructor for zkp_<...>_t don't set any values and handles only proof fields.
 *  When using <...>_prove, all public and secret fields of zkp_<...>_t needs to be already populated (externally).
 *  Calling <...>_prove sets only the proof fields.
 *  When using <...>_verify, all public and proof fields of zkp_<...>_t need to be already populated.
 *  Calling <...>_verify return 0/1 (fail/pass).
 * 
 */

#ifndef __CMP20_ECDSA_MPC_ZKP_ENC_IN_RANGE_H__
#define __CMP20_ECDSA_MPC_ZKP_ENC_IN_RANGE_H__

#include "zkp_common.h"

typedef struct
{ 
  uint64_t k_range_bytes;
  scalar_t challenge_modulus;
  ring_pedersen_public_t *rped_pub;
  paillier_public_key_t *paillier_pub;
  scalar_t K;                 // PAILLIER_MODULUS_BYTES * 2
} zkp_encryption_in_range_public_t; 

typedef struct
{  
  scalar_t k;       // k_range_bytes
  scalar_t rho;     // PAILLIER_MODULUS_BYTES
} zkp_encryption_in_range_secret_t; 

typedef struct
{
  scalar_t S;       // RING_PED_MODULUS_BYTES
  scalar_t A;       // PAILLIER_MODULUS_BYTES * 2
  scalar_t C;       // RING_PED_MODULUS_BYTES
  scalar_t z_1;     // k_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
  scalar_t z_2;     // PAILLIER_MODULUS_BYTES
  scalar_t z_3;     // RING_PED_MODULUS_BYTES + k_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
} zkp_encryption_in_range_proof_t;


zkp_encryption_in_range_proof_t *
     zkp_encryption_in_range_new              ();
void zkp_encryption_in_range_free             (zkp_encryption_in_range_proof_t *proof);
void zkp_encryption_in_range_prove            (zkp_encryption_in_range_proof_t *proof, const zkp_encryption_in_range_secret_t *secret, const zkp_encryption_in_range_public_t *public, const zkp_aux_info_t *aux);
int  zkp_encryption_in_range_verify           (const zkp_encryption_in_range_proof_t *proof, const zkp_encryption_in_range_public_t *public, const zkp_aux_info_t *aux);
void zkp_encryption_in_range_proof_to_bytes   (uint8_t **bytes, uint64_t *byte_len, const zkp_encryption_in_range_proof_t *proof, uint64_t k_range_bytes, int move_to_end);
void zkp_encryption_in_range_proof_from_bytes (zkp_encryption_in_range_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, uint64_t k_range_bytes, int move_to_end);

#endif