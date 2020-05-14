#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "zkp_common.h"

#ifndef __CMP20_ECDSA_MPC_ZKP_PAILLIER_BLUM_H__
#define __CMP20_ECDSA_MPC_ZKP_PAILLIER_BLUM_H__

#define ZKP_PAILLIER_BLUM_MODULUS_PROOF_BYTES  (PAILLIER_MODULUS_BYTES*(1 + 2*STATISTICAL_SECURITY) + 2*STATISTICAL_SECURITY)

typedef struct
{
  paillier_public_key_t *public;

  paillier_private_key_t * private;

  struct {
    scalar_t w;
    scalar_t x[STATISTICAL_SECURITY];
    scalar_t z[STATISTICAL_SECURITY];
    uint8_t a[STATISTICAL_SECURITY];
    uint8_t b[STATISTICAL_SECURITY];
  } proof;
} zkp_paillier_blum_modulus_t;

zkp_paillier_blum_modulus_t *
      zkp_paillier_blum_new    ();
void  zkp_paillier_blum_free   (zkp_paillier_blum_modulus_t *zkp);
void  zkp_paillier_blum_prove  (zkp_paillier_blum_modulus_t *zkp, const zkp_aux_info_t *aux);
int   zkp_paillier_blum_verify (zkp_paillier_blum_modulus_t *zkp, const zkp_aux_info_t *aux);

#endif