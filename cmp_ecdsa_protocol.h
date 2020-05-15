#include "primitives.h"

#ifndef __CMP20_ECDSA_MPC_PROTOCOL_H__
#define __CMP20_ECDSA_MPC_PROTOCOL_H__

#define KAPPA_RANDOM_ORACLE_BYTES 64      // RO input and output

typedef uint8_t hash_chunk[KAPPA_RANDOM_ORACLE_BYTES];

// super_sesion_id is required for every phases of the protocol
typedef struct 
{
  uint64_t id;
  hash_chunk srid;

  ec_group_t ec;
  gr_elem_t ec_gen;
  scalar_t ec_order;

  uint64_t num_parties;
  uint64_t *parties_ids;

  uint8_t  *bytes;
  uint64_t byte_len;

} cmp_session_id_t;

typedef struct 
{
  scalar_t tau;
  zkp_schnorr_t *psi;

  hash_chunk srid;
  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_broadcast;

  uint64_t total_time;

} cmp_key_generation_info_t;

typedef struct 
{

  scalar_t *reshare_secret_x_i_j;
  scalar_t *encrypted_secret_i_j;
  gr_elem_t *reshare_public_X_i_j;
  
  zkp_paillier_blum_modulus_t *psi;
  zkp_paillier_blum_modulus_t *psi_prime;
  zkp_ring_pedersen_param_t   *psi_double_prime;

  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_broadcast;

} cmp_refresh_aux_info_t;

typedef struct cmp_party_ctx_t
{
  cmp_session_id_t *sid;

  uint64_t party_id;
  uint64_t num_parties;
  struct cmp_party_ctx_t **parties;     // All parties (pointers), to get their info (just for testing, instead of communication channels)

  scalar_t secret_x;                    // private key share
  gr_elem_t public_X;                   // public key share

  paillier_private_key_t *paillier_priv;
  ring_pedersen_public_t *rped_pub;

  cmp_key_generation_info_t *kg_data;
  cmp_refresh_aux_info_t    *refresh_data;

} cmp_party_ctx_t;


void cmp_sample_bytes (uint8_t *rand_byte, uint64_t byte_len);

cmp_session_id_t *
      cmp_session_id_new            (uint64_t id, uint64_t num_parties, uint64_t *partys_ids);
void  cmp_session_id_free           (cmp_session_id_t *ssid);
void  cmp_session_id_append_bytes   (cmp_session_id_t *sid, const uint8_t *data, uint64_t data_len);

cmp_party_ctx_t *
      cmp_party_ctx_new   (uint64_t party_id, uint64_t num_parties, cmp_session_id_t *ssid);
void  cmp_party_ctx_free  (cmp_party_ctx_t *party_ctx);

void  cmp_key_generation_init           (cmp_party_ctx_t *party);
void  cmp_key_generation_finish         (cmp_party_ctx_t *party);
void  cmp_key_generation_round_1_exec   (cmp_party_ctx_t *party);
void  cmp_key_generation_round_2_exec   (cmp_party_ctx_t *party);
void  cmp_key_generation_round_3_exec   (cmp_party_ctx_t *party);
void  cmp_key_generation_final_exec     (cmp_party_ctx_t *party);

#endif