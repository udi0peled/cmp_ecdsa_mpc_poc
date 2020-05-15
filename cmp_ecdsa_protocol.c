#include "common.h"
#include "cmp_ecdsa_protocol.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <time.h>

#define ERR_STR "\nXXXXX ERROR XXXXX\n\n"
void cmp_sample_bytes (uint8_t *rand_bytes, uint64_t byte_len)
{
  RAND_bytes(rand_bytes, byte_len);
}

/** 
 *  Super Session
 */

cmp_session_id_t *cmp_session_id_new(uint64_t id, uint64_t num_parties, uint64_t *partys_ids)
{
  cmp_session_id_t *sid = malloc(sizeof(*sid));

  sid->id = id;
  sid->num_parties = num_parties;
  sid->parties_ids = calloc(num_parties, sizeof(uint64_t));
  for (uint64_t i = 0; i < sid->num_parties; ++i) sid->parties_ids[i] = partys_ids[i];

  sid->ec = ec_group_new();
  sid->ec_gen = ec_group_generator(sid->ec);
  sid->ec_order = ec_group_order(sid->ec);

  
  sid->byte_len =  sizeof(sid->id)
                    + GROUP_ELEMENT_BYTES
                    + GROUP_ORDER_BYTES
                    + sizeof(sid->num_parties)
                    + sid->num_parties * sizeof(uint64_t);

  sid->bytes = malloc(sid->byte_len);
  uint8_t *bytes_pos = sid->bytes;
  
  memcpy(bytes_pos, &sid->id, sizeof(sid->id));                               bytes_pos += sizeof(sid->id);
  group_elem_to_bytes(bytes_pos, GROUP_ELEMENT_BYTES, sid->ec_gen, sid->ec);  bytes_pos += GROUP_ELEMENT_BYTES;
  scalar_to_bytes(bytes_pos, GROUP_ORDER_BYTES, sid->ec_order);                bytes_pos += GROUP_ORDER_BYTES;
  memcpy(bytes_pos, &sid->num_parties, sizeof(sid->num_parties));             bytes_pos += sizeof(sid->num_parties);
  for (uint64_t i = 0; i < sid->num_parties; ++i)
  {
    memcpy(bytes_pos, &sid->parties_ids[i], sizeof(uint64_t));          bytes_pos += sizeof(uint64_t);
  }

  assert(sid->bytes + sid->byte_len == bytes_pos);

  return sid;
}

void cmp_session_id_free (cmp_session_id_t *sid)
{ 
  free(sid->parties_ids);
  ec_group_free(sid->ec);
  free(sid->bytes);
  free(sid);
}

void cmp_session_id_append_bytes(cmp_session_id_t *sid, const uint8_t *data, uint64_t data_len)
{
  sid->bytes = realloc(sid->bytes, sid->byte_len + data_len);
  memcpy(sid->bytes + sid->byte_len, data, data_len);
  sid->byte_len += data_len;
}

/**
 *  Party Context for Protocol Execution
 */

cmp_party_ctx_t *cmp_party_ctx_new (uint64_t party_id, uint64_t num_parties, cmp_session_id_t *sid)
{
  cmp_party_ctx_t *party = malloc(sizeof(*party));
  
  party->party_id = party_id;
  party->num_parties = num_parties;
  party->parties = NULL;             // should be set externally
  party->kg_data = NULL;              // set during KG

  party->sid = sid;

  party->public_X = group_elem_new(party->sid->ec);
  party->secret_x = scalar_new();

  return party;
}

void  cmp_party_ctx_free  (cmp_party_ctx_t *party)
{
  scalar_free(party->secret_x);
  group_elem_free(party->public_X);
  free(party);
}

/** 
 *  Key Generation
 */

void cmp_key_generation_init(cmp_party_ctx_t *party)
{
  party->kg_data = malloc(sizeof(*party->kg_data));
  party->kg_data->psi = zkp_schnorr_new();
  party->kg_data->psi->public.G = party->sid->ec;
  party->kg_data->psi->public.g = party->sid->ec_gen;
  party->kg_data->tau = scalar_new();
  party->kg_data->total_time = 0;
}

void cmp_key_generation_finish(cmp_party_ctx_t *party)
{
  scalar_free(party->kg_data->tau);
  zkp_schnorr_free(party->kg_data->psi);
  free(party->kg_data);
}

void cmp_key_generation_round_1_commit(hash_chunk V, const cmp_party_ctx_t *party)
{
  uint8_t *temp_bytes;

  SHA512_CTX *sha_ctx = malloc(sizeof(*sha_ctx));
  SHA512_Init(sha_ctx);

  SHA512_Update(sha_ctx, party->sid->bytes, party->sid->byte_len);

  SHA512_Update(sha_ctx, &party->party_id, sizeof(party->party_id));
  SHA512_Update(sha_ctx, party->kg_data->srid, sizeof(hash_chunk));
  
  temp_bytes = malloc(GROUP_ELEMENT_BYTES);
  group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, party->public_X, party->sid->ec);
  SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, party->kg_data->psi->proof.A, party->sid->ec);
  SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  SHA512_Update(sha_ctx, party->kg_data->u, sizeof(hash_chunk));

  SHA512_Final(V, sha_ctx);

  free(temp_bytes);
  free(sha_ctx);
}

void  cmp_key_generation_round_1_exec (cmp_party_ctx_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  scalar_sample_in_range(party->secret_x, party->sid->ec_order, 0);
  group_operation(party->public_X, NULL, party->sid->ec_gen, party->secret_x, party->sid->ec);

  cmp_sample_bytes(party->kg_data->srid, sizeof(party->kg_data->srid));

  zkp_schnorr_commit(party->kg_data->psi, party->kg_data->tau);

  cmp_sample_bytes(party->kg_data->u, sizeof(party->kg_data->u));

  cmp_key_generation_round_1_commit(party->kg_data->V, party);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  party->kg_data->total_time += time_diff;

  printf("Round 1. Party %lu broadcasts (sid, i, V_i).\t%lu B, %lu ms\n", party->party_id, 2*sizeof(uint64_t) + sizeof(hash_chunk), time_diff);
  printf("sid = %lu\t", party->sid->id);
  printHexBytes("V_i = ", party->kg_data->V, sizeof(hash_chunk), "\n");
  printHexBytes("srid_i = ", party->kg_data->srid, sizeof(hash_chunk), "\n");
}

void  cmp_key_generation_round_2_exec (cmp_party_ctx_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  // Echo broadcast - Send hash of all V_i commitments
  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t i = 0; i < party->num_parties; ++i) SHA512_Update(&sha_ctx, party->parties[i]->kg_data->V, sizeof(hash_chunk));
  SHA512_Final(party->kg_data->echo_broadcast, &sha_ctx);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  party->kg_data->total_time += time_diff;

  printf("Round 2. Party %lu publishes (sid, i, srid_i, X_i, A_i, u_i, echo_broadcast).\t%lu B, %lu ms\n", party->party_id, 
    2*sizeof(uint64_t) + 4*sizeof(hash_chunk) + 2*GROUP_ELEMENT_BYTES, time_diff);
  printHexBytes("echo_broadcast = ", party->kg_data->echo_broadcast, sizeof(hash_chunk), "\n");
}

static zkp_aux_info_t *cmp_aux_info_round_3_psi(cmp_party_ctx_t *party)
{
  zkp_aux_info_t *aux = malloc(sizeof(*aux));

  aux->info_len = party->sid->byte_len + sizeof(uint64_t) + sizeof(hash_chunk);
  aux->info = malloc(aux->info_len);
  uint8_t *aux_pos = aux->info;
  memcpy(aux_pos, party->sid->bytes, party->sid->byte_len);   aux_pos += party->sid->byte_len;
  memcpy(aux_pos, &party->party_id, sizeof(uint64_t));        aux_pos += sizeof(uint64_t);
  memcpy(aux_pos, party->sid->srid, sizeof(hash_chunk));      aux_pos += sizeof(hash_chunk);

  assert(aux->info + aux->info_len == aux_pos);

  return aux;
}

void  cmp_key_generation_round_3_exec (cmp_party_ctx_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  // Later will set to xor of all parties
  memset(party->sid->srid, 0x00, sizeof(hash_chunk));

  int *verified_decomm = calloc(party->num_parties, sizeof(int));
  int *verified_echo = calloc(party->num_parties, sizeof(int));

  hash_chunk ver_data;
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    // Verify commited V_i
    cmp_key_generation_round_1_commit(ver_data, party->parties[j]);
    verified_decomm[j] = memcmp(ver_data, party->parties[j]->kg_data->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment
    verified_echo[j] = memcmp(party->kg_data->echo_broadcast, party->parties[j]->kg_data->echo_broadcast, sizeof(hash_chunk)) == 0;

    // Set srid as xor of all party's srid_i
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) party->sid->srid[pos] ^= party->parties[j]->kg_data->srid[pos];
  }

  // Generate Schnorr ZKProof - psi

  zkp_aux_info_t * aux = cmp_aux_info_round_3_psi(party);

  party->kg_data->psi->public.X = party->public_X;
  party->kg_data->psi->secret.x = party->secret_x;
  zkp_schnorr_prove(party->kg_data->psi, aux, party->kg_data->tau);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  party->kg_data->total_time += time_diff;
  
  for (uint8_t j = 0; j < party->num_parties; ++j){
    if (!verified_decomm) printf("%sParty %lu decommitment of V_i from Party %lu\n",ERR_STR, party->party_id, party->parties[j]->party_id);
    if (!verified_echo) printf("%sParty %lu received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->party_id, party->parties[j]->party_id);
  }

  free(aux->info);
  free(aux);
  free(verified_decomm);
  free(verified_echo);
  
  printf("Round 3. Party %lu publishes (sid, i, psi_i).\t%lu B, %lu ms\n", party->party_id, 2*sizeof(uint64_t) + ZKP_SCHNORR_PROOF_BYTES, time_diff);
  printHexBytes("common srid = ", party->sid->srid, sizeof(hash_chunk), "\n");
}

void cmp_key_generation_final_exec(cmp_party_ctx_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  int *verified_psi = calloc(party->num_parties, sizeof(int));

  // Verify all Schnorr ZKP received from parties  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    zkp_aux_info_t *aux = cmp_aux_info_round_3_psi(party);
    verified_psi[j] = zkp_schnorr_verify(party->parties[j]->kg_data->psi, aux);
    free(aux->info);
    free(aux);
  }

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  party->kg_data->total_time += time_diff;
  
  for (uint8_t j = 0; j < party->num_parties; ++j){
    if (!verified_psi) printf("%sParty %lu schnorr zkp (psi) failed verification from Party %lu\n",ERR_STR, party->party_id, party->parties[j]->party_id);
  }
  
  free(verified_psi);
  
  printf("Final. Party %lu stores (srid, all X, secret x_i).\t%lu B, %lu ms\n", party->party_id, 
    sizeof(hash_chunk) + party->num_parties * GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES, time_diff);
}
