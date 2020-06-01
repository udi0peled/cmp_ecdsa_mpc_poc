#include "primitives.h"

#ifndef __CMP20_ECDSA_MPC_PROTOCOL_H__
#define __CMP20_ECDSA_MPC_PROTOCOL_H__

#define KAPPA_RANDOM_ORACLE_BYTES 64                              // RO input and output

#define ELL_ZKP_RANGE_PARAMETER_BYTES (GROUP_ORDER_BYTES)
#define ELL_PRIME_ZKP_RANGE_PARAMETER_BYTES (5*GROUP_ORDER_BYTES)
#define CALIGRAPHIC_I_ZKP_RANGE_BYTES (ELL_ZKP_RANGE_PARAMETER_BYTES)
#define CALIGRAPHIC_J_ZKP_RANGE_BYTES (EPS_ZKP_SLACK_PARAMETER_BYTES + ELL_ZKP_RANGE_PARAMETER_BYTES*3)

typedef uint8_t hash_chunk[KAPPA_RANDOM_ORACLE_BYTES];

typedef struct 
{
  scalar_t  secret_x;
  gr_elem_t public_X;

  scalar_t        tau;
  zkp_schnorr_t   *psi;
  zkp_aux_info_t  *aux;

  hash_chunk srid;
  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_broadcast;

  scalar_t *received_A;
  scalar_t *received_X;

  uint64_t run_time;
} cmp_key_generation_t;

typedef struct 
{
  paillier_private_key_t  *paillier_priv;
  ring_pedersen_private_t *rped_priv;

  scalar_t  *reshare_secret_x_j;
  scalar_t  *encrypted_reshare_j;
  gr_elem_t *reshare_public_X_j;
  
  zkp_aux_info_t              *aux;
  scalar_t                    *tau;
  zkp_schnorr_t               **psi_sch;
  zkp_paillier_blum_modulus_t *psi_mod;
  zkp_ring_pedersen_param_t   *psi_rped;

  hash_chunk rho;
  hash_chunk combined_rho;
  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_broadcast;

  uint64_t prime_time;
  uint64_t run_time;
} cmp_refresh_aux_info_t;

typedef struct 
{
  scalar_t G;
  scalar_t K;
  scalar_t k;
  scalar_t rho;
  scalar_t nu;
  scalar_t gamma;
  scalar_t delta;
  scalar_t chi;

  scalar_t *alpha_j;
  scalar_t *beta_j;
  scalar_t *alphahat_j;
  scalar_t *betahat_j;
  scalar_t *D_j;
  scalar_t *F_j;
  scalar_t *Dhat_j;
  scalar_t *Fhat_j;

  gr_elem_t Delta;
  gr_elem_t Gamma;
  gr_elem_t combined_Gamma;

  zkp_aux_info_t                            *aux;
  zkp_encryption_in_range_t                 **psi_enc;
  zkp_operation_paillier_commitment_range_t **psi_affp;
  zkp_operation_group_commitment_range_t    **psi_affg;
  zkp_group_vs_paillier_range_t             **psi_logG;
  zkp_group_vs_paillier_range_t             **psi_logK;

  hash_chunk echo_broadcast;

  uint64_t run_time;
} cmp_presigning_t;

typedef struct cmp_party_t
{
  uint64_t id;
  uint64_t index;
  uint64_t num_parties;

  scalar_t  secret_x;                       // private key share
  gr_elem_t *public_X;                      // public key shares of all partys (by index)

  paillier_private_key_t *paillier_priv;
  paillier_public_key_t  **paillier_pub;   
  ring_pedersen_public_t **rped_pub;

  ec_group_t ec;
  gr_elem_t ec_gen;
  scalar_t ec_order;

  uint64_t *parties_ids;

  hash_chunk sid;
  hash_chunk srid;
  hash_chunk sid_hash;

  cmp_key_generation_t    *key_generation_data;
  cmp_refresh_aux_info_t  *refresh_data;
  cmp_presigning_t        *presigning_data;

  gr_elem_t R;
  scalar_t k;
  scalar_t chi;

  struct cmp_party_t **parties;
} cmp_party_t;


void cmp_sample_bytes (uint8_t *rand_byte, uint64_t byte_len);

void cmp_party_new  (cmp_party_t **parties, uint64_t num_parties, const uint64_t *parties_ids, uint64_t index, const hash_chunk sid);
void cmp_party_free (cmp_party_t *party);

void cmp_key_generation_init         (cmp_party_t *party);
void cmp_key_generation_clean        (cmp_party_t *party);
void cmp_key_generation_round_1_exec (cmp_party_t *party);
void cmp_key_generation_round_2_exec (cmp_party_t *party);
void cmp_key_generation_round_3_exec (cmp_party_t *party);
void cmp_key_generation_final_exec   (cmp_party_t *party);

void cmp_refresh_aux_info_init         (cmp_party_t *party);
void cmp_refresh_aux_info_clean        (cmp_party_t *party);
void cmp_refresh_aux_info_round_1_exec (cmp_party_t *party);
void cmp_refresh_aux_info_round_2_exec (cmp_party_t *party);
void cmp_refresh_aux_info_round_3_exec (cmp_party_t *party);
void cmp_refresh_aux_info_final_exec   (cmp_party_t *party);

void cmp_presigning_init         (cmp_party_t *party);
void cmp_presigning_clean        (cmp_party_t *party);
void cmp_presigning_round_1_exec (cmp_party_t *party);
void cmp_presigning_round_2_exec (cmp_party_t *party);
void cmp_presigning_round_3_exec (cmp_party_t *party);
void cmp_presigning_final_exec   (cmp_party_t *party);

void cmp_signature_share (scalar_t r, scalar_t sigma, const cmp_party_t *party, const scalar_t msg);

#endif