/**
 * 
 *  Name:
 *  zkp_paillier_blum_modulus
 *  
 *  Description:
 *  Paillier Blum Modulus Zero Knowledge Proof for modulus of PAILLIER_MODULUS_BYTES byte length (hardcoded in verification).
 * 
 *  Usage:
 *  Constructor and destructor for zkp_<...>_t don't set any values and handles only proof fields.
 *  When using <...>_prove, all public and secret fields of zkp_<...>_t needs to be already populated (externally).
 *  Calling <...>_prove sets only the proof fields.
 *  When using <...>_verify, all public and proof fields of zkp_<...>_t need to be already populated.
 *  Calling <...>_verify return 0/1 (fail/pass).
 * 
 */

#ifndef __CMP20_ECDSA_MPC_ZKP_PAILLIER_BLUM_H__
#define __CMP20_ECDSA_MPC_ZKP_PAILLIER_BLUM_H__

#include "zkp_common.h"

typedef struct
{
  paillier_public_key_t *public;        // public
  paillier_private_key_t *private;      // secret

  struct {
    scalar_t w;
    scalar_t x[STATISTICAL_SECURITY];
    scalar_t z[STATISTICAL_SECURITY];
    uint8_t a[STATISTICAL_SECURITY];
    uint8_t b[STATISTICAL_SECURITY];
  } proof;
} zkp_paillier_blum_modulus_t;

zkp_paillier_blum_modulus_t *
         zkp_paillier_blum_new         ();
void     zkp_paillier_blum_free        (zkp_paillier_blum_modulus_t *zkp);
void     zkp_paillier_blum_prove       (zkp_paillier_blum_modulus_t *zkp, const zkp_aux_info_t *aux);
int      zkp_paillier_blum_verify      (zkp_paillier_blum_modulus_t *zkp, const zkp_aux_info_t *aux);
uint64_t zkp_paillier_blum_proof_bytes ();

#endif