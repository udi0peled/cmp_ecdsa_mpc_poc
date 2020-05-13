#include "algebraic_elements.h"
#include "zkp_common.h"

#ifndef __CMP20_ECDSA_MPC_ZKP_SCHNORR_H__
#define __CMP20_ECDSA_MPC_ZKP_SCHNORR_H__

#define ZKP_SCHNORR_PROOF_BYTES (GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES)

typedef struct
{
  struct { 
    ec_group_t G;
    gr_elem_t g;    // GROUP_ELEMENT_BYTES
    gr_elem_t X;    // GROUP_ELEMENT_BYTES
  } public;

  struct {
    scalar_t x;     // GROUP_ORDER_BYTES
  } secret;

  struct {
    gr_elem_t A;    // GROUP_ELEMENT_BYTES
    scalar_t z;     // GROUP_ORDER_BYTES
  } proof;
} zkp_schnorr_t;

zkp_schnorr_t *
      zkp_schnorr_new     ();
void  zkp_schnorr_free    (zkp_schnorr_t *zkp);
void  zkp_schnorr_commit  (zkp_schnorr_t *zkp, scalar_t alpha);
void  zkp_schnorr_prove   (zkp_schnorr_t *zkp, const zkp_aux_info_t *aux, const scalar_t alpha);      // alpha == NULL, sample random
int   zkp_schnorr_verify  (zkp_schnorr_t *zkp, const zkp_aux_info_t *aux);


#endif