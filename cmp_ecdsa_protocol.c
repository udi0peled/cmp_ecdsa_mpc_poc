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

void cmp_party_new (cmp_party_t **parties, uint64_t num_parties, uint64_t index, uint64_t id, cmp_session_id_t *ssid)
{
  cmp_party_t *party = malloc(sizeof(*party));
  
  parties[index] = party;
  party->parties = parties;

  party->sid = ssid;
  
  party->id = id;
  party->index = index;
  party->num_parties = num_parties;
  
  party->secret_x = NULL;
  party->public_X = NULL;

  party->paillier_priv = NULL;
  party->rped_pub      = NULL;

  party->key_generation_data   = NULL;
  party->refresh_aux_info_data = NULL;
}

void cmp_party_free (cmp_party_t *party)
{
  if (party->secret_x) scalar_free(party->secret_x);
  if (party->public_X) group_elem_free(party->public_X);
  free(party);
}

/** 
 *  Key Generation
 */

void cmp_key_generation_init(cmp_party_t *party)
{
  cmp_key_generation_t *kgd = malloc(sizeof(*party->key_generation_data));
  party->key_generation_data = kgd;

  kgd->secret_x = scalar_new();
  kgd->public_X = group_elem_new(party->sid->ec);

  kgd->tau = scalar_new();
  kgd->psi = zkp_schnorr_new();

  kgd->run_time = 0;
}

void cmp_key_generation_clean(cmp_party_t *party)
{
  cmp_key_generation_t *kgd = party->key_generation_data;

  zkp_aux_info_free(kgd->aux);
  zkp_schnorr_free(kgd->psi);
  scalar_free(kgd->tau);
  scalar_free(kgd->secret_x);
  group_elem_free(kgd->public_X);

  free(kgd);
}

void cmp_key_generation_round_1_commit(hash_chunk V, const cmp_session_id_t *sid, uint64_t party_id, const cmp_party_t *party)
{
  cmp_key_generation_t *kgd = party->key_generation_data;

  uint8_t temp_bytes[GROUP_ELEMENT_BYTES];

  SHA512_CTX *sha_ctx = malloc(sizeof(*sha_ctx));
  SHA512_Init(sha_ctx);
  SHA512_Update(sha_ctx, sid->bytes, sid->byte_len);
  SHA512_Update(sha_ctx, &party_id, sizeof(uint64_t));
  SHA512_Update(sha_ctx, kgd->srid, sizeof(hash_chunk));
  
  group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, kgd->public_X, sid->ec);
  SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, kgd->psi->proof.A, sid->ec);
  SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  SHA512_Update(sha_ctx, kgd->u, sizeof(hash_chunk));
  SHA512_Final(V, sha_ctx);

  free(sha_ctx);
}

void  cmp_key_generation_round_1_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_key_generation_t *kgd = party->key_generation_data;

  scalar_sample_in_range(kgd->secret_x, party->sid->ec_order, 0);
  group_operation(kgd->public_X, NULL, party->sid->ec_gen, kgd->secret_x, party->sid->ec);

  kgd->psi->public.G = party->sid->ec;
  kgd->psi->public.g = party->sid->ec_gen;
  zkp_schnorr_commit(kgd->psi, kgd->tau);

  cmp_sample_bytes(kgd->srid, sizeof(hash_chunk));
  cmp_sample_bytes(kgd->u, sizeof(hash_chunk));
  cmp_key_generation_round_1_commit(kgd->V, party->sid, party->id, party);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;

  printf("Round 1. Party %lu broadcasts (sid, i, V_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(uint64_t) + sizeof(hash_chunk), time_diff);
  printf("session id = %lu\n", party->sid->id);
  printHexBytes("V_i = ", kgd->V, sizeof(hash_chunk), "\n");
  printHexBytes("srid_i = ", kgd->srid, sizeof(hash_chunk), "\n");
}

void  cmp_key_generation_round_2_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_key_generation_t *kgd = party->key_generation_data;

  // Echo broadcast - Send hash of all V_i commitments
  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t i = 0; i < party->num_parties; ++i) SHA512_Update(&sha_ctx, party->parties[i]->key_generation_data->V, sizeof(hash_chunk));
  SHA512_Final(kgd->echo_broadcast, &sha_ctx);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;

  printf("Round 2. Party %lu publishes (sid, i, srid_i, X_i, A_i, u_i, echo_broadcast).\t%lu B, %lu ms\n", party->id, 
    2*sizeof(uint64_t) + 4*sizeof(hash_chunk) + 2*GROUP_ELEMENT_BYTES, time_diff);
  printHexBytes("echo_broadcast = ", kgd->echo_broadcast, sizeof(hash_chunk), "\n");
}

void  cmp_key_generation_round_3_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_key_generation_t *kgd = party->key_generation_data;

  // Later will set to xor of all parties
  memset(party->sid->srid, 0x00, sizeof(hash_chunk));

  int *verified_decomm = calloc(party->num_parties, sizeof(int));
  int *verified_echo = calloc(party->num_parties, sizeof(int));

  hash_chunk ver_data;
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    // Verify commited V_i
    cmp_key_generation_round_1_commit(ver_data, party->sid, party->sid->parties_ids[j], party->parties[j]);
    verified_decomm[j] = memcmp(ver_data, party->parties[j]->key_generation_data->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment -- ToDo: expand to identification of malicious party
    verified_echo[j] = memcmp(kgd->echo_broadcast, party->parties[j]->key_generation_data->echo_broadcast, sizeof(hash_chunk)) == 0;

    // Set srid as xor of all party's srid_i
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) party->sid->srid[pos] ^= party->parties[j]->key_generation_data->srid[pos];
  }

  // Generate Schnorr ZKProof - psi

  // Aux Info (ssid, i, srid)
  kgd->aux = zkp_aux_info_new(party->sid->byte_len + sizeof(uint64_t) + sizeof(hash_chunk), party->sid->bytes, party->sid->byte_len);
  uint64_t aux_pos = party->sid->byte_len;
  zkp_aux_info_update(kgd->aux, aux_pos, &party->id, sizeof(uint64_t));                aux_pos += sizeof(uint64_t);
  zkp_aux_info_update(kgd->aux, aux_pos, party->sid->srid, sizeof(hash_chunk));        aux_pos += sizeof(hash_chunk);
  assert(kgd->aux->info_len == aux_pos);

  // Set claim to prove
  kgd->psi->public.X = kgd->public_X;
  kgd->psi->secret.x = kgd->secret_x;
  zkp_schnorr_prove(kgd->psi, kgd->aux, kgd->tau);

  for (uint8_t j = 0; j < party->num_parties; ++j){
    if (verified_decomm[j] != 1) printf("%sParty %lu decommitment of V_i from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
    if (verified_echo[j] != 1) printf("%sParty %lu received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
  }

  free(verified_decomm);
  free(verified_echo);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;
  
  printf("Round 3. Party %lu publishes (sid, i, psi_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(uint64_t) + ZKP_SCHNORR_PROOF_BYTES, time_diff);
  printHexBytes("common srid = ", party->sid->srid, sizeof(hash_chunk), "\n");
}

void cmp_key_generation_final_exec(cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_key_generation_t *kgd = party->key_generation_data;

  int *verified_psi = calloc(party->num_parties, sizeof(int));

  // Verify all Schnorr ZKP received from parties  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    zkp_aux_info_update(kgd->aux, party->sid->byte_len, &party->sid->parties_ids[j], sizeof(uint64_t));     // Update i to commiting player
    verified_psi[j] = zkp_schnorr_verify(party->parties[j]->key_generation_data->psi, kgd->aux);
    verified_psi[j] &= group_elem_equal(party->parties[j]->key_generation_data->psi->proof.A, party->parties[j]->key_generation_data->psi->proof.A, party->sid->ec);      // Check A's of rounds 2 and 3
  }

  for (uint64_t j = 0; j < party->num_parties; ++j){
    if (verified_psi[j] != 1) printf("%sParty %lu schnorr zkp (psi) failed verification from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
  }
  
  free(verified_psi);

  // Transfer to party's values
  if (party->secret_x) scalar_free(party->secret_x);
  party->secret_x = kgd->secret_x;
  kgd->secret_x = NULL;

  if (party->public_X) group_elem_free(party->public_X);
  party->public_X = kgd->public_X;
  kgd->public_X = NULL;

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;
  
  printf("Final. Party %lu stores (srid, all X, secret x_i).\t%lu B, %lu ms\n", party->id, 
    sizeof(hash_chunk) + party->num_parties * GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES, time_diff);
}

/** 
 *  Key Refresh and Auxiliary Information 
 */

void cmp_refresh_aux_info_init(cmp_party_t *party)
{
  cmp_refresh_aux_info_t *raid = malloc(sizeof(*raid));
  party->refresh_aux_info_data = raid;

  raid->psi_mod  = zkp_paillier_blum_new();
  raid->psi_rped = zkp_ring_pedersen_param_new();
  raid->psi_sch  = calloc(party->num_parties, sizeof(zkp_schnorr_t)); 
  raid->tau      = calloc(party->num_parties, sizeof(scalar_t));
  
  raid->reshare_secret_x_i_j = calloc(party->num_parties, sizeof(scalar_t));
  raid->encrypted_secret_i_j = calloc(party->num_parties, sizeof(scalar_t));
  raid->reshare_public_X_i_j = calloc(party->num_parties, sizeof(gr_elem_t));

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    raid->tau[j]                   = scalar_new();
    raid->reshare_secret_x_i_j[j]  = scalar_new();
    raid->encrypted_secret_i_j[j]  = scalar_new();
    raid->reshare_public_X_i_j[j]  = group_elem_new(party->sid->ec);
    raid->psi_sch[j]               = zkp_schnorr_new();
  }

  raid->prime_time = 0;
  raid->run_time = 0;
}

void cmp_refresh_aux_info_clean(cmp_party_t *party)
{
  cmp_refresh_aux_info_t *raid = party->refresh_aux_info_data;

  zkp_aux_info_free(raid->aux);
  paillier_encryption_free_keys(raid->paillier_priv, NULL);
  ring_pedersen_free_param(raid->rped_priv, NULL);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    scalar_free(raid->tau[j]);
    scalar_free(raid->reshare_secret_x_i_j[j]);
    scalar_free(raid->encrypted_secret_i_j[j]);
    group_elem_free(raid->reshare_public_X_i_j[j]);
    zkp_schnorr_free(raid->psi_sch[j]);
  }

  free(raid->reshare_secret_x_i_j);
  free(raid->encrypted_secret_i_j);
  free(raid->reshare_public_X_i_j);

  free(raid->psi_mod);
  free(raid->psi_rped);
  free(raid->psi_sch);
  free(raid->tau);

  free(raid);
}

void cmp_refresh_aux_info_round_1_commit(hash_chunk V, const cmp_session_id_t *sid, uint64_t party_id, const cmp_party_t *party)
{
  cmp_refresh_aux_info_t *raid = party->refresh_aux_info_data;

  uint8_t temp_bytes[(GROUP_ELEMENT_BYTES >= PAILLIER_MODULUS_BYTES ? GROUP_ELEMENT_BYTES : PAILLIER_MODULUS_BYTES)];     // Enough for both

  SHA512_CTX *sha_ctx = malloc(sizeof(*sha_ctx));
  SHA512_Init(sha_ctx);
  SHA512_Update(sha_ctx, sid->bytes, sid->byte_len);
  SHA512_Update(sha_ctx, &party_id, sizeof(uint64_t));

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, raid->reshare_public_X_i_j[j], sid->ec);
    SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  }

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, raid->psi_sch[j]->proof.A, sid->ec);
    SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  }

  scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, party->paillier_priv->pub.N);
  SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, party->rped_pub->N);
  SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, party->rped_pub->s);
  SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, party->rped_pub->t);
  SHA512_Update(sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  SHA512_Update(sha_ctx, raid->rho, sizeof(hash_chunk));
  SHA512_Update(sha_ctx, raid->u, sizeof(hash_chunk));
  SHA512_Final(V, sha_ctx);

  free(sha_ctx);
}

void cmp_refresh_aux_info_round_1_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_aux_info_t *raid = party->refresh_aux_info_data;

  raid->paillier_priv = paillier_encryption_generate_key();

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  raid->prime_time = time_diff;

  raid->rped_priv = ring_pedersen_generate_param(raid->paillier_priv->p, raid->paillier_priv->q);
  
  scalar_set(raid->reshare_secret_x_i_j[party->index], 0);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    // Dont choose your own values, only later if needed
    if (j == party->index) continue; 

    scalar_sample_in_range(raid->reshare_secret_x_i_j[j], party->sid->ec_order, 0);
    group_operation(raid->reshare_public_X_i_j[j], NULL, party->sid->ec_gen, raid->reshare_secret_x_i_j[j], party->sid->ec);
    scalar_sub(raid->reshare_secret_x_i_j[party->index], raid->reshare_secret_x_i_j[party->index], raid->reshare_secret_x_i_j[j], party->sid->ec_order);

    raid->psi_sch[j]->public.G = party->sid->ec;
    raid->psi_sch[j]->public.g = party->sid->ec_gen;
    zkp_schnorr_commit(raid->psi_sch[j], raid->tau[j]);
  }

  cmp_sample_bytes(raid->rho, sizeof(hash_chunk));
  cmp_sample_bytes(raid->u, sizeof(hash_chunk));
  cmp_refresh_aux_info_round_1_commit(raid->V, party->sid, party->id, party);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  raid->run_time += time_diff;

  printf("Round 1. Party %lu broadcasts (sid, i, V_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(uint64_t) + sizeof(hash_chunk), time_diff);
  printf("session id = %lu\n", party->sid->id);
  printHexBytes("V_i = ", party->key_generation_data->V, sizeof(hash_chunk), "\n");
  printHexBytes("srid_i = ", party->key_generation_data->srid, sizeof(hash_chunk), "\n");
}

void  cmp_refresh_aux_info_round_2_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_aux_info_t *raid = party->refresh_aux_info_data;

  // Echo broadcast - Send hash of all V_i commitments
  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t i = 0; i < party->num_parties; ++i) SHA512_Update(&sha_ctx, party->parties[i]->key_generation_data->V, sizeof(hash_chunk));
  SHA512_Final(party->key_generation_data->echo_broadcast, &sha_ctx);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  party->key_generation_data->run_time += time_diff;

  printf("Round 2. Party %lu publishes (sid, i, srid_i, X_i, A_i, u_i, echo_broadcast).\t%lu B, %lu ms\n", party->id, 
    2*sizeof(uint64_t) + 4*sizeof(hash_chunk) + 2*GROUP_ELEMENT_BYTES, time_diff);
  printHexBytes("echo_broadcast = ", party->key_generation_data->echo_broadcast, sizeof(hash_chunk), "\n");
}

void  cmp_refresh_aux_info_round_3_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_aux_info_t *raid = party->refresh_aux_info_data;

  // Later will set to xor of all parties
  memset(party->sid->srid, 0x00, sizeof(hash_chunk));

  int *verified_decomm = calloc(party->num_parties, sizeof(int));
  int *verified_echo = calloc(party->num_parties, sizeof(int));

  hash_chunk ver_data;
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    // Verify commited V_i
    cmp_refresh_aux_info_round_1_commit(ver_data, party->sid, party->sid->parties_ids[j], party->parties[j]);
    verified_decomm[j] = memcmp(ver_data, party->parties[j]->key_generation_data->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment -- ToDo: expand to identification of malicious party
    verified_echo[j] = memcmp(party->key_generation_data->echo_broadcast, party->parties[j]->key_generation_data->echo_broadcast, sizeof(hash_chunk)) == 0;

    // Set srid as xor of all party's srid_i
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) party->sid->srid[pos] ^= party->parties[j]->key_generation_data->srid[pos];
  }

  // Generate Schnorr ZKProof - psi

  // Aux Info (ssid, i, srid)
  party->key_generation_data->aux = zkp_aux_info_new(party->sid->byte_len + sizeof(uint64_t) + sizeof(hash_chunk), party->sid->bytes, party->sid->byte_len);
  uint64_t aux_pos = party->sid->byte_len;
  zkp_aux_info_update(party->key_generation_data->aux, aux_pos, &party->id, sizeof(uint64_t));                aux_pos += sizeof(uint64_t);
  zkp_aux_info_update(party->key_generation_data->aux, aux_pos, party->sid->srid, sizeof(hash_chunk));        aux_pos += sizeof(hash_chunk);
  assert(party->key_generation_data->aux->info_len == aux_pos);

  // Set claim to prove
  party->key_generation_data->psi->public.X = party->public_X;
  party->key_generation_data->psi->secret.x = party->secret_x;
  zkp_schnorr_prove(party->key_generation_data->psi, party->key_generation_data->aux, party->key_generation_data->tau);

  for (uint8_t j = 0; j < party->num_parties; ++j){
    if (verified_decomm[j] != 1) printf("%sParty %lu decommitment of V_i from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
    if (verified_echo[j] != 1) printf("%sParty %lu received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
  }

  free(verified_decomm);
  free(verified_echo);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  party->key_generation_data->run_time += time_diff;
  
  printf("Round 3. Party %lu publishes (sid, i, psi_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(uint64_t) + ZKP_SCHNORR_PROOF_BYTES, time_diff);
  printHexBytes("common srid = ", party->sid->srid, sizeof(hash_chunk), "\n");
}

void cmp_refresh_aux_info_final_exec(cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_aux_info_t *raid = party->refresh_aux_info_data;

  int *verified_psi = calloc(party->num_parties, sizeof(int));

  // Verify all Schnorr ZKP received from parties  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    zkp_aux_info_update(party->key_generation_data->aux, party->sid->byte_len, &party->sid->parties_ids[j], sizeof(uint64_t));     // Update i to commiting player
    verified_psi[j] = zkp_schnorr_verify(party->parties[j]->key_generation_data->psi, party->key_generation_data->aux);
    verified_psi[j] &= group_elem_equal(party->parties[j]->key_generation_data->psi->proof.A, party->parties[j]->key_generation_data->psi->proof.A, party->sid->ec);      // Check A's of rounds 2 and 3
  }

  for (uint64_t j = 0; j < party->num_parties; ++j){
    if (verified_psi[j] != 1) printf("%sParty %lu schnorr zkp (psi) failed verification from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
  }
  
  free(verified_psi);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  party->key_generation_data->run_time += time_diff;
  
  printf("Final. Party %lu stores (srid, all X, secret x_i).\t%lu B, %lu ms\n", party->id, 
    sizeof(hash_chunk) + party->num_parties * GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES, time_diff);
}
