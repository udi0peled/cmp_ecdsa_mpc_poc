#include "primitives.h"

#ifndef __CMP20_ECDSA_MPC_PROTOCOL_H__
#define __CMP20_ECDSA_MPC_PROTOCOL_H__

#define KAPPA_RANDOM_ORACLE_BYTES 64      // RO input and output

typedef uint8_t hash_chunk[KAPPA_RANDOM_ORACLE_BYTES];

typedef struct 
{
  uint64_t id;

  ec_group_t ec;
  gr_elem_t ec_gen;
  scalar_t ec_order;

  uint64_t num_parties;
  uint64_t *parties_ids;

} cmp_super_session_id_t;

typedef struct 
{
  scalar_t tau;
  gr_elem_t X;
  zkp_schnorr_t *psi;

  hash_chunk srid;
  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_broadcast;

} cmp_key_generation_ctx_t;

typedef struct cmp_party_ctx_t
{
    uint64_t party_id;
    uint64_t num_parties;
    struct cmp_party_ctx_t **parties;      // list of all parties pointers, to get their info (just for testing, instead of sending)

    cmp_super_session_id_t *ssid;
    hash_chunk srid;

    scalar_t x;               // private key share
    gr_elem_t public_X;       // public key share
    gr_elem_t *vec_X;         // all parties public key shares

    cmp_key_generation_ctx_t *kg_ctx;

} cmp_party_ctx_t;


void cmp_sample_bytes (uint8_t *rand_byte, uint64_t byte_len);

cmp_super_session_id_t *
          cmp_super_session_id_new    (uint64_t id, uint64_t num_parties);
void      cmp_super_session_id_free   (cmp_super_session_id_t *ssid);
uint64_t  cmp_super_session_num_bytes (const cmp_super_session_id_t *ssid);
void      cmp_super_session_get_bytes (uint8_t *rand_byte, const cmp_super_session_id_t *ssid);

cmp_party_ctx_t *
      cmp_party_ctx_new   (uint64_t party_id, uint64_t num_parties, cmp_super_session_id_t *ssid);
void  cmp_party_ctx_free  (cmp_party_ctx_t *party_ctx);

void  cmp_key_generation_init           (cmp_party_ctx_t *party);
void  cmp_key_generation_finish         (cmp_party_ctx_t *party);
void  cmp_key_generation_round_1_exec   (cmp_party_ctx_t *party);
void  cmp_key_generation_round_2_exec   (cmp_party_ctx_t *party);
void  cmp_key_generation_round_3_exec   (cmp_party_ctx_t *party);

#endif