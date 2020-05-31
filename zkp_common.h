#include <assert.h>
#include <string.h>

#include "algebraic_elements.h"
#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "ring_pedersen_parameters.h"

#ifndef __CMP20_ECDSA_MPC_ZKP_COMMON_H__
#define __CMP20_ECDSA_MPC_ZKP_COMMON_H__

#define STATISTICAL_SECURITY 80
#define EPS_ZKP_SLACK_PARAMETER_BYTES (2*GROUP_ORDER_BYTES)

/** 
 * General Auxiliary Information for ZKProofs
 */

typedef struct
{
  uint8_t *info;
  uint64_t info_len;
} zkp_aux_info_t;

zkp_aux_info_t *
      zkp_aux_info_new    (uint64_t set_byte_len, const void *init_bytes, uint64_t init_byte_len);
void  zkp_aux_info_update (zkp_aux_info_t *aux, uint64_t at_pos, const void *update_bytes, uint64_t update_byte_len);
void  zkp_aux_info_free   (zkp_aux_info_t *aux);

void fiat_shamir_bytes            (uint8_t *digest, uint64_t digest_len, const uint8_t *data, uint64_t data_len);
void fiat_shamir_scalars_in_range (scalar_t *results, uint64_t num_res, const scalar_t range, const uint8_t *data, uint64_t data_len);

#endif