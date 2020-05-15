#include "common.h"
#include "cmp_ecdsa_protocol.h"
#include <openssl/sha.h>
#include <openssl/rand.h>

#define ERR_STR "\nXXXXX ERROR XXXXX\n\n"
void cmp_sample_bytes (uint8_t *rand_bytes, uint64_t byte_len)
{
  RAND_bytes(rand_bytes, byte_len);
}

/** 
 *  Super Session
 */

cmp_super_session_id_t *cmp_super_session_id_new(uint64_t id, uint64_t num_parties)
{
  cmp_super_session_id_t *ssid = malloc(sizeof(*ssid));

  ssid->id = id;
  ssid->num_parties = num_parties;
  ssid->parties_ids = calloc(num_parties, sizeof(uint64_t));

  ssid->ec = ec_group_new();
  ssid->ec_gen = ec_group_generator(ssid->ec);
  ssid->ec_order = ec_group_order(ssid->ec);

  return ssid;
}

void cmp_super_session_id_free (cmp_super_session_id_t *ssid)
{ 
  free(ssid->parties_ids);
  ec_group_free(ssid->ec);

  free(ssid);
}

uint64_t  cmp_super_session_num_bytes(const cmp_super_session_id_t *ssid)
{
  return  sizeof(ssid->id)
          + GROUP_ELEMENT_BYTES
          + GROUP_ORDER_BYTES
          + sizeof(ssid->num_parties)
          + ssid->num_parties * sizeof(*ssid->parties_ids);
}

void cmp_super_session_get_bytes(uint8_t *res_bytes, const cmp_super_session_id_t *ssid)
{
  memcpy(res_bytes, &ssid->id, sizeof(ssid->id));                               res_bytes += sizeof(ssid->id);
  group_elem_to_bytes(res_bytes, GROUP_ELEMENT_BYTES, ssid->ec_gen, ssid->ec);  res_bytes += GROUP_ELEMENT_BYTES;
  scalar_to_bytes(res_bytes, GROUP_ORDER_BYTES, ssid->ec_order);                res_bytes += GROUP_ORDER_BYTES;
  memcpy(res_bytes, &ssid->num_parties, sizeof(ssid->num_parties));             res_bytes += sizeof(ssid->num_parties);
  for (uint64_t i = 0; i < ssid->num_parties; ++i)
  {
    memcpy(res_bytes, &ssid->parties_ids[i], sizeof(uint64_t));          res_bytes += sizeof(uint64_t);
  }
}

/**
 *  Party Context for Protocol Execution
 */

cmp_party_ctx_t *cmp_party_ctx_new (uint64_t party_id, uint64_t num_parties, cmp_super_session_id_t *ssid)
{
  cmp_party_ctx_t *party = malloc(sizeof(*party));
  
  party->party_id = party_id;
  party->num_parties = num_parties;
  party->parties = NULL;             // should be set externally
  party->kg_ctx = NULL;              // set during KG

  party->ssid = ssid;

  party->public_X = group_elem_new(party->ssid->ec);
  party->x = scalar_new();
  party->vec_X = calloc(num_parties, sizeof(gr_elem_t));
  for (uint64_t i = 0; i < num_parties; ++i) party->vec_X[i] = group_elem_new(party->ssid->ec);

  return party;
}

void  cmp_party_ctx_free  (cmp_party_ctx_t *party)
{
  scalar_free(party->x);
  group_elem_free(party->public_X);
  for (uint64_t i = 0; i < party->num_parties; ++i) group_elem_free(party->vec_X[i]);
  free(party->vec_X);
  free(party);
}

/** 
 *  Key Generation
 */

void cmp_key_generation_init(cmp_party_ctx_t *party)
{
  party->kg_ctx = malloc(sizeof(*party->kg_ctx));
  party->kg_ctx->psi = zkp_schnorr_new();
  party->kg_ctx->psi->public.G = party->ssid->ec;
  party->kg_ctx->psi->public.g = party->ssid->ec_gen;
  party->kg_ctx->X = group_elem_new(party->ssid->ec);
  party->kg_ctx->tau = scalar_new();
}

void cmp_key_generation_finish(cmp_party_ctx_t *party)
{
  group_elem_free(party->kg_ctx->X);
  scalar_free(party->kg_ctx->tau);
  zkp_schnorr_free(party->kg_ctx->psi);
  free(party->kg_ctx);
}

void cmp_key_gen_round_1_commit(hash_chunk V, const cmp_party_ctx_t *party)
{
  uint8_t *temp_bytes;
  uint8_t temp_byte_len;

  SHA512_CTX *sha_ctx = malloc(sizeof(*sha_ctx));
  SHA512_Init(sha_ctx);

  temp_byte_len = cmp_super_session_num_bytes(party->ssid);
  temp_bytes = malloc(temp_byte_len);
  cmp_super_session_get_bytes(temp_bytes, party->ssid);
  SHA512_Update(sha_ctx, temp_bytes, temp_byte_len);

  SHA512_Update(sha_ctx, &party->party_id, sizeof(party->party_id));
  SHA512_Update(sha_ctx, party->kg_ctx->srid, sizeof(hash_chunk));
  
  temp_byte_len = GROUP_ELEMENT_BYTES;
  temp_bytes = realloc(temp_bytes, temp_byte_len);
  group_elem_to_bytes(temp_bytes, temp_byte_len, party->public_X, party->ssid->ec);
  SHA512_Update(sha_ctx, temp_bytes, temp_byte_len);

  temp_byte_len = GROUP_ELEMENT_BYTES;
  temp_bytes = realloc(temp_bytes, temp_byte_len);
  group_elem_to_bytes(temp_bytes, temp_byte_len, party->kg_ctx->psi->proof.A, party->ssid->ec);
  SHA512_Update(sha_ctx, temp_bytes, temp_byte_len);

  SHA512_Update(sha_ctx, party->kg_ctx->u, sizeof(hash_chunk));

  SHA512_Final(V, sha_ctx);

  free(temp_bytes);
  free(sha_ctx);
}

void  cmp_key_generation_round_1_exec (cmp_party_ctx_t *party)
{
  scalar_sample_in_range(party->x, party->ssid->ec_order, 0);
  group_operation(party->public_X, NULL, party->ssid->ec_gen, party->x, party->ssid->ec);

  cmp_sample_bytes(party->kg_ctx->srid, sizeof(party->kg_ctx->srid));

  zkp_schnorr_commit(party->kg_ctx->psi, party->kg_ctx->tau);

  cmp_sample_bytes(party->kg_ctx->u, sizeof(party->kg_ctx->u));

  cmp_key_gen_round_1_commit(party->kg_ctx->V, party);

  printf("Round 1. Party %lu broadcasts (ssid, i, V_i).\t%lu B\n", party->party_id, 2*sizeof(uint64_t) + sizeof(hash_chunk));
  printf("ssid = %lu\t", party->ssid->id);
  printf("i = %lu\t", party->party_id);
  printHexBytes("V_i = ", party->kg_ctx->V, sizeof(hash_chunk), "\n");
}

void  cmp_key_generation_round_2_exec (cmp_party_ctx_t *party)
{
  // Echo broadcast - Send hash of all V_i commitments
  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t i = 0; i < party->num_parties; ++i) SHA512_Update(&sha_ctx, party->parties[i]->kg_ctx->V, sizeof(hash_chunk));
  SHA512_Final(party->kg_ctx->echo_broadcast, &sha_ctx);

  printf("Round 2. Party %lu broadcasts (ssid, i, srid_i, X_i, A_i, u_i, echo_broadcast).\t%lu B\n", party->party_id, 
    2*sizeof(uint64_t) + 4*sizeof(hash_chunk) + 2*GROUP_ELEMENT_BYTES);
  printHexBytes("echo_broadcast = ", party->kg_ctx->echo_broadcast, sizeof(hash_chunk), "\n");
}

void  cmp_key_generation_round_3_exec (cmp_party_ctx_t *party)
{
  int verified = 0;

  // Verify Commited V_i and echo_broadcast

  hash_chunk ver_data;
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    cmp_key_gen_round_1_commit(ver_data, party->parties[j]);
    verified = memcmp(ver_data, party->parties[j]->kg_ctx->V, sizeof(hash_chunk)) == 0;
    if (!verified) printf("%sParty %lu decommitment of V_i from Party %lu\n",ERR_STR, party->party_id, party->parties[j]->party_id);

    verified = memcmp(party->kg_ctx->echo_broadcast, party->parties[j]->kg_ctx->echo_broadcast, sizeof(hash_chunk)) == 0;
    if (!verified) printf("%sParty %lu received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->party_id, party->parties[j]->party_id);
  }
  // UDIBUG: continue round 3....
  
  printf("Round 3. Party %lu broadcasts (ssid, i, srid_i, X_i, A_i, u_i, echo_broadcast).\t%lu B\n", party->party_id, 
    2*sizeof(uint64_t) + 4*sizeof(hash_chunk) + 2*GROUP_ELEMENT_BYTES);
  printHexBytes("echo_broadcast = ", party->kg_ctx->echo_broadcast, sizeof(hash_chunk), "\n");
}