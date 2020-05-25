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
  
  party->secret_x = scalar_new();
  party->public_X = calloc(num_parties, sizeof(gr_elem_t));

  party->paillier_priv = NULL;
  party->paillier_pub  = calloc(num_parties, sizeof(paillier_public_key_t *));
  party->rped_pub      = calloc(num_parties, sizeof(ring_pedersen_public_t *));

  for (uint64_t i = 0; i < num_parties; ++i)
  {
    party->public_X[i] = group_elem_new(party->sid->ec);
  }

  party->key_generation_data   = NULL;
  party->refresh_data = NULL;
}

void cmp_party_free (cmp_party_t *party)
{
  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    group_elem_free(party->public_X[i]);
    paillier_encryption_free_keys(NULL, party->paillier_pub[i]);
    ring_pedersen_free_param(NULL, party->rped_pub[i]);
  }

  paillier_encryption_free_keys(party->paillier_priv, NULL); 
  scalar_free(party->secret_x);
  free(party->paillier_pub);
  free(party->rped_pub);
  free(party->public_X);
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
  kgd->aux = zkp_aux_info_new(party->sid->byte_len + sizeof(uint64_t) + sizeof(hash_chunk), NULL, 0); // prepeare for (ssid, i, srid)

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

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, sid->bytes, sid->byte_len);
  SHA512_Update(&sha_ctx, &party_id, sizeof(uint64_t));
  SHA512_Update(&sha_ctx, kgd->srid, sizeof(hash_chunk));
  
  group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, kgd->public_X, sid->ec);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, kgd->psi->proof.A, sid->ec);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  SHA512_Update(&sha_ctx, kgd->u, sizeof(hash_chunk));
  SHA512_Final(V, &sha_ctx);
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

  printf("# Round 1. Party %lu broadcasts (sid, i, V_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(uint64_t) + sizeof(hash_chunk), time_diff);
  printf("session id = %lu\n", party->sid->id);
  printf("V_%lu = ", party->index); printHexBytes("", kgd->V, sizeof(hash_chunk), "\n");
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

  printf("# Round 2. Party %lu publishes (sid, i, srid_i, X_i, A_i, u_i, echo_broadcast_i).\t%lu B, %lu ms\n", party->id, 
    2*sizeof(uint64_t) + 4*sizeof(hash_chunk) + 2*GROUP_ELEMENT_BYTES, time_diff);
  printf("X_%lu = ", party->index); printECPOINT("secp256k1.Point(", kgd->public_X, party->sid->ec, ")\n", 1);
  printf("A_%lu = ", party->index); printECPOINT("secp256k1.Point(", kgd->psi->proof.A, party->sid->ec, ")\n", 1);
  printf("srid_%lu = ", party->index); printHexBytes("", kgd->srid, sizeof(hash_chunk), "\n");
  printf("u_%lu = ", party->index); printHexBytes("", kgd->u, sizeof(hash_chunk), "\n");
  printf("echo_broadcast_%lu = ", party->index); printHexBytes("", kgd->echo_broadcast, sizeof(hash_chunk), "\n");
}

void  cmp_key_generation_round_3_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_key_generation_t *kgd = party->key_generation_data;

  int *verified_decomm = calloc(party->num_parties, sizeof(int));
  int *verified_echo = calloc(party->num_parties, sizeof(int));

  hash_chunk ver_data;
  memcpy(party->sid->srid, kgd->srid, sizeof(hash_chunk));
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    // Verify commited V_i
    cmp_key_generation_round_1_commit(ver_data, party->sid, party->sid->parties_ids[j], party->parties[j]);
    verified_decomm[j] = memcmp(ver_data, party->parties[j]->key_generation_data->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment -- ToDo: expand to identification of malicious party
    verified_echo[j] = memcmp(kgd->echo_broadcast, party->parties[j]->key_generation_data->echo_broadcast, sizeof(hash_chunk)) == 0;

    // Set srid as xor of all party's srid_i
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) party->sid->srid[pos] ^= party->parties[j]->key_generation_data->srid[pos];
  }

  for (uint8_t j = 0; j < party->num_parties; ++j){
    if (j == party->index) continue;
    if (verified_decomm[j] != 1) printf("%sParty %lu: decommitment of V_i from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
    if (verified_echo[j] != 1)   printf("%sParty %lu: received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
  }

  free(verified_decomm);
  free(verified_echo);

  // Aux Info (ssid, i, srid)
  uint64_t aux_pos = 0;
  zkp_aux_info_update(kgd->aux, aux_pos, party->sid->bytes, party->sid->byte_len);     aux_pos += party->sid->byte_len;
  zkp_aux_info_update(kgd->aux, aux_pos, &party->id, sizeof(uint64_t));                aux_pos += sizeof(uint64_t);
  zkp_aux_info_update(kgd->aux, aux_pos, party->sid->srid, sizeof(hash_chunk));        aux_pos += sizeof(hash_chunk);
  assert(kgd->aux->info_len == aux_pos);

  // Set Schnorr ZKP public claim and secret, then prove
  kgd->psi->public.X = kgd->public_X;
  kgd->psi->secret.x = kgd->secret_x;
  zkp_schnorr_prove(kgd->psi, kgd->aux, kgd->tau);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;
  
  printf("# Round 3. Party %lu publishes (sid, i, psi_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(uint64_t) + ZKP_SCHNORR_PROOF_BYTES, time_diff);
  printHexBytes("combined srid = ", party->sid->srid, sizeof(hash_chunk), "\n");
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
    if (j == party->index) continue;
    zkp_aux_info_update(kgd->aux, party->sid->byte_len, &party->sid->parties_ids[j], sizeof(uint64_t));     // Update i to commiting player
    verified_psi[j] = zkp_schnorr_verify(party->parties[j]->key_generation_data->psi, kgd->aux);
    verified_psi[j] &= group_elem_equal(party->parties[j]->key_generation_data->psi->proof.A, party->parties[j]->key_generation_data->psi->proof.A, party->sid->ec);      // Check A's of rounds 2 and 3
  }

  for (uint64_t j = 0; j < party->num_parties; ++j){
    if (j == party->index) continue;
    if (verified_psi[j] != 1) printf("%sParty %lu: schnorr zkp (psi) failed verification from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
  }
  
  free(verified_psi);

  // Set party's values
  scalar_copy(party->secret_x, kgd->secret_x);
  for (uint64_t j = 0; j < party->num_parties; ++j) group_elem_copy(party->public_X[j], party->parties[j]->key_generation_data->public_X);
  
  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;
  
  printf("# Final. Party %lu stores (srid, all X, secret x_i).\t%lu B, %lu ms\n", party->id, 
    sizeof(hash_chunk) + party->num_parties * GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES, time_diff);
  printf("x_%lu = ", party->index); printBIGNUM("", party->secret_x, "\n");
}

/******************************************** 
 * 
 *   Key Refresh and Auxiliary Information 
 * 
 ********************************************/

void cmp_refresh_aux_info_init(cmp_party_t *party)
{
  cmp_refresh_aux_info_t *reda = malloc(sizeof(*reda));
  party->refresh_data = reda;

  reda->paillier_priv = NULL;
  reda->rped_priv = NULL;

  reda->psi_mod  = zkp_paillier_blum_new();
  reda->psi_rped = zkp_ring_pedersen_param_new();
  reda->psi_sch  = calloc(party->num_parties, sizeof(zkp_schnorr_t)); 
  reda->tau      = calloc(party->num_parties, sizeof(scalar_t));
  reda->aux      = zkp_aux_info_new(party->sid->byte_len + sizeof(uint64_t) + sizeof(hash_chunk), NULL, 0);   // prepare for (sid, i, rho)
  
  reda->reshare_secret_x_j = calloc(party->num_parties, sizeof(scalar_t));
  reda->encrypted_reshare_j = calloc(party->num_parties, sizeof(scalar_t));
  reda->reshare_public_X_j = calloc(party->num_parties, sizeof(gr_elem_t));

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    reda->tau[j]                 = scalar_new();
    reda->reshare_secret_x_j[j]  = scalar_new();
    reda->encrypted_reshare_j[j] = scalar_new();
    reda->reshare_public_X_j[j]  = group_elem_new(party->sid->ec);
    reda->psi_sch[j]             = zkp_schnorr_new();
  }

  reda->prime_time = 0;
  reda->run_time = 0;
}

void cmp_refresh_aux_info_clean(cmp_party_t *party)
{
  cmp_refresh_aux_info_t *reda = party->refresh_data;

  zkp_aux_info_free(reda->aux);
  paillier_encryption_free_keys(reda->paillier_priv, NULL);
  ring_pedersen_free_param(reda->rped_priv, NULL);
  zkp_paillier_blum_free(reda->psi_mod);
  zkp_ring_pedersen_param_free(reda->psi_rped);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    scalar_free(reda->tau[j]);
    scalar_free(reda->reshare_secret_x_j[j]);
    scalar_free(reda->encrypted_reshare_j[j]);
    group_elem_free(reda->reshare_public_X_j[j]);
    zkp_schnorr_free(reda->psi_sch[j]);
  }

  free(reda->reshare_secret_x_j);
  free(reda->encrypted_reshare_j);
  free(reda->reshare_public_X_j);
  free(reda->psi_sch);
  free(reda->tau);
  free(reda);
}

void cmp_refresh_aux_info_round_1_commit(hash_chunk V, const cmp_session_id_t *sid, uint64_t party_id, const cmp_party_t *party)
{
  cmp_refresh_aux_info_t *reda = party->refresh_data;

  uint8_t temp_bytes[(GROUP_ELEMENT_BYTES >= PAILLIER_MODULUS_BYTES ? GROUP_ELEMENT_BYTES : PAILLIER_MODULUS_BYTES)];     // Enough for both

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, sid->bytes, sid->byte_len);
  SHA512_Update(&sha_ctx, &party_id, sizeof(uint64_t));

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, reda->reshare_public_X_j[j], sid->ec);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  }

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, reda->psi_sch[j]->proof.A, sid->ec);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  }

  scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, reda->paillier_priv->pub.N);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, reda->rped_priv->pub.N);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, reda->rped_priv->pub.s);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, reda->rped_priv->pub.t);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  SHA512_Update(&sha_ctx, reda->rho, sizeof(hash_chunk));
  SHA512_Update(&sha_ctx, reda->u, sizeof(hash_chunk));
  SHA512_Final(V, &sha_ctx);
}

void cmp_refresh_aux_info_round_1_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_aux_info_t *reda = party->refresh_data;

  reda->paillier_priv = paillier_encryption_generate_key();

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->prime_time = time_diff;

  reda->rped_priv = ring_pedersen_generate_param(reda->paillier_priv->p, reda->paillier_priv->q);
  
  // Sample other parties' reshares, set negative of sum for current
  scalar_set(reda->reshare_secret_x_j[party->index], 0);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    // Also initialize relevant zkp
    reda->psi_sch[j]->public.G = party->sid->ec;
    reda->psi_sch[j]->public.g = party->sid->ec_gen;
    zkp_schnorr_commit(reda->psi_sch[j], reda->tau[j]);

    // Dont choose your own values, only later if needed
    if (j == party->index) continue; 

    scalar_sample_in_range(reda->reshare_secret_x_j[j], party->sid->ec_order, 0);
    group_operation(reda->reshare_public_X_j[j], NULL, party->sid->ec_gen, reda->reshare_secret_x_j[j], party->sid->ec);
    scalar_sub(reda->reshare_secret_x_j[party->index], reda->reshare_secret_x_j[party->index], reda->reshare_secret_x_j[j], party->sid->ec_order);
  }
  group_operation(reda->reshare_public_X_j[party->index], NULL, party->sid->ec_gen, reda->reshare_secret_x_j[party->index], party->sid->ec);

  cmp_sample_bytes(reda->rho, sizeof(hash_chunk));
  cmp_sample_bytes(reda->u, sizeof(hash_chunk));
  cmp_refresh_aux_info_round_1_commit(reda->V, party->sid, party->id, party);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;

  printf("# Round 1. Party %lu broadcasts (sid, i, V_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(uint64_t) + sizeof(hash_chunk), time_diff);
  printf("session id = %lu\n", party->sid->id);
  printf("V_%lu = ", party->index); printHexBytes("", reda->V, sizeof(hash_chunk), "\n");
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    printf("x_%lue%lu = ", party->index, j); printBIGNUM("", reda->reshare_secret_x_j[j], "\n");
  }
}

void  cmp_refresh_aux_info_round_2_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_aux_info_t *reda = party->refresh_data;

  // Echo broadcast - Send hash of all V_i commitments
  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t i = 0; i < party->num_parties; ++i) SHA512_Update(&sha_ctx, party->parties[i]->refresh_data->V, sizeof(hash_chunk));
  SHA512_Final(reda->echo_broadcast, &sha_ctx);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;

  printf("# Round 2. Party %lu publishes (sid, i, X_i^{1...n}, A_i^{1...n}, Paillier N_i, s_i, t_i, rho_i, u_i, echo_broadcast).\t%lu B, %lu ms (gen N_i) + %lu ms (rest)\n", 
    party->id, 2*sizeof(uint64_t) + party->num_parties*2*GROUP_ELEMENT_BYTES  + 3*PAILLIER_MODULUS_BYTES + 3*sizeof(hash_chunk), reda->prime_time, time_diff);
  
  printf("echo_broadcast_%lu = ", party->index); printHexBytes("echo_broadcast = ", reda->echo_broadcast, sizeof(hash_chunk), "\n");
  printf("rho_%lu = ", party->index); printHexBytes("", reda->rho, sizeof(hash_chunk), "\n");
  printf("u_%lu = ", party->index); printHexBytes("", reda->u, sizeof(hash_chunk), "\n");
  printf("N_%lu = ", party->index); printBIGNUM("", reda->rped_priv->pub.N, "\n");
  printf("s_%lu = ", party->index); printBIGNUM("", reda->rped_priv->pub.s, "\n");
  printf("t_%lu = ", party->index); printBIGNUM("", reda->rped_priv->pub.t, "\n");

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    printf("X_%lue%lu = ", party->index, j); printECPOINT("secp256k1.Point(", reda->reshare_public_X_j[j], party->sid->ec, ")\n", 1);
    printf("A_%lue%lu = ", party->index, j); printECPOINT("secp256k1.Point(", reda->psi_sch[j]->proof.A, party->sid->ec, ")\n", 1);
  }
}

void  cmp_refresh_aux_info_round_3_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_aux_info_t *reda = party->refresh_data;
  
  gr_elem_t combined_public = group_elem_new(party->sid->ec);

  int *verified_modulus_size = calloc(party->num_parties, sizeof(int));
  int *verified_public_shares = calloc(party->num_parties, sizeof(int));
  int *verified_decomm = calloc(party->num_parties, sizeof(int));
  int *verified_echo = calloc(party->num_parties, sizeof(int));

  hash_chunk ver_data;
  memcpy(reda->combined_rho, reda->rho, sizeof(hash_chunk));
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    // Verify modulus size
    verified_modulus_size[j] = scalar_bitlength(party->parties[j]->refresh_data->paillier_priv->pub.N) == 8*PAILLIER_MODULUS_BYTES;

    // Verify shared public X_j is valid
    group_operation(combined_public, NULL, NULL, NULL, party->sid->ec);
    for (uint64_t k = 0; k < party->num_parties; ++k) {
      group_operation(combined_public, combined_public, party->parties[j]->refresh_data->reshare_public_X_j[k], NULL, party->sid->ec);
    }
    verified_public_shares[j] = group_elem_is_ident(combined_public, party->sid->ec) == 1;

    // Verify commited V_i
    cmp_refresh_aux_info_round_1_commit(ver_data, party->sid, party->sid->parties_ids[j], party->parties[j]);
    verified_decomm[j] = memcmp(ver_data, party->parties[j]->refresh_data->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment -- ToDo: expand to identification of malicious party
    verified_echo[j] = memcmp(reda->echo_broadcast, party->parties[j]->refresh_data->echo_broadcast, sizeof(hash_chunk)) == 0;

    // Set combined rho as xor of all party's rho_i
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) reda->combined_rho[pos] ^= party->parties[j]->refresh_data->rho[pos];
  }

  for (uint8_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    if (verified_modulus_size[j] != 1)  printf("%sParty %lu: N_i bitlength from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
    if (verified_public_shares[j] != 1) printf("%sParty %lu: invalid X_j_k sharing from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
    if (verified_decomm[j] != 1)        printf("%sParty %lu: decommitment of V_i from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
    if (verified_echo[j] != 1)          printf("%sParty %lu: received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
  }

  free(verified_modulus_size);
  free(verified_public_shares);
  free(verified_decomm);
  free(verified_echo);
  group_elem_free(combined_public);

    // Aux Info for ZKP (ssid, i, combined rho)
  uint64_t aux_pos = 0;
  zkp_aux_info_update(reda->aux, aux_pos, party->sid->bytes, party->sid->byte_len);     aux_pos += party->sid->byte_len;
  zkp_aux_info_update(reda->aux, aux_pos, &party->id, sizeof(uint64_t));                aux_pos += sizeof(uint64_t);
  zkp_aux_info_update(reda->aux, aux_pos, reda->combined_rho, sizeof(hash_chunk));      aux_pos += sizeof(hash_chunk);
  assert(reda->aux->info_len == aux_pos);

  // Generate ZKP, set public claim and secret, then prove
  reda->psi_mod->public = &reda->paillier_priv->pub;
  reda->psi_mod->private = reda->paillier_priv;
  zkp_paillier_blum_prove(reda->psi_mod, reda->aux);

  reda->psi_rped->rped_pub = &reda->rped_priv->pub;
  reda->psi_rped->secret = reda->rped_priv;
  zkp_ring_pedersen_param_prove(reda->psi_rped, reda->aux);

  scalar_t temp_paillier_rand = scalar_new();
  for (uint8_t j = 0; j < party->num_parties; ++j)
  {
    // Encrypt all secret reshares (including own) - ToDo add echo broadcast on these
    paillier_encryption_sample(temp_paillier_rand, &party->parties[j]->refresh_data->paillier_priv->pub);
    paillier_encryption_encrypt(reda->encrypted_reshare_j[j], reda->reshare_secret_x_j[j], temp_paillier_rand, &party->parties[j]->refresh_data->paillier_priv->pub);

    reda->psi_sch[j]->public.X = reda->reshare_public_X_j[j];
    reda->psi_sch[j]->secret.x = reda->reshare_secret_x_j[j];
    zkp_schnorr_prove(reda->psi_sch[j], reda->aux, reda->tau[j]);
  }
  scalar_free(temp_paillier_rand);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;
  
  printf("# Round 3. Party %lu publishes (sid, i, psi_mod, psi_rped, psi_sch^j, Enc_j(x_i^j)).\t%lu B, %lu ms\n", party->id, 
    2*sizeof(uint64_t) + ZKP_PAILLIER_BLUM_MODULUS_PROOF_BYTES + ZKP_RING_PEDERSEN_PARAM_PROOF_BYTES + (party->num_parties-1)*ZKP_SCHNORR_PROOF_BYTES + party->num_parties*2*PAILLIER_MODULUS_BYTES, time_diff);
  printHexBytes("combined rho = ", reda->combined_rho, sizeof(hash_chunk), "\n");
}

void cmp_refresh_aux_info_final_exec(cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_aux_info_t *reda = party->refresh_data;

  int *verified_reshare  = calloc(party->num_parties, sizeof(int));
  int *verified_psi_mod  = calloc(party->num_parties, sizeof(int));
  int *verified_psi_rped = calloc(party->num_parties, sizeof(int));
  int *verified_psi_sch  = calloc(party->num_parties*party->num_parties, sizeof(int));

  // Verify all Schnorr ZKP and values received from parties  

  scalar_t received_reshare = scalar_new();
  scalar_t sum_received_reshares = scalar_new();
  gr_elem_t ver_public = group_elem_new(party->sid->ec);
  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  { 
    // Decrypt and verify reshare secret vs public   
    paillier_encryption_decrypt(received_reshare, party->parties[j]->refresh_data->encrypted_reshare_j[party->index], reda->paillier_priv);     // TODO: reduce MODULU q!!!
    scalar_add(sum_received_reshares, sum_received_reshares, received_reshare, party->sid->ec_order);
    group_operation(ver_public, NULL, party->sid->ec_gen, received_reshare, party->sid->ec);
    verified_reshare[j] = group_elem_equal(ver_public, party->parties[j]->refresh_data->reshare_public_X_j[party->index], party->sid->ec) == 1;

    if (j == party->index) continue; 

    zkp_aux_info_update(reda->aux, party->sid->byte_len, &party->sid->parties_ids[j], sizeof(uint64_t));                  // Update i to commiting player
    verified_psi_mod[j] = zkp_paillier_blum_verify(party->parties[j]->refresh_data->psi_mod, reda->aux) == 1;
    verified_psi_rped[j] = zkp_ring_pedersen_param_verify(party->parties[j]->refresh_data->psi_rped, reda->aux) == 1;

    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      verified_psi_sch[k + party->num_parties*j] = (zkp_schnorr_verify(party->parties[j]->refresh_data->psi_sch[k], reda->aux) == 1)
       && (group_elem_equal(party->parties[j]->refresh_data->psi_sch[k]->proof.A, party->parties[j]->refresh_data->psi_sch[k]->proof.A, party->sid->ec) == 1);      // Check A's of rounds 2 and 3
    }
  }
  scalar_free(received_reshare);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    if (verified_reshare[j] != 1)  printf("%sParty %lu: Public reshare inconsistent from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
    if (verified_psi_mod[j] != 1)  printf("%sParty %lu: Paillier-Blum ZKP failed verification from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
    if (verified_psi_rped[j] != 1) printf("%sParty %lu: Ring-Pedersen ZKP failed verification from Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j]);
    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      if (verified_psi_sch[k + party->num_parties*j] != 1) printf("%sParty %lu: Schnorr ZKP failed verification from Party %lu for Party %lu\n",ERR_STR, party->id, party->sid->parties_ids[j], party->sid->parties_ids[k]);
    }
  }

  free(verified_reshare);
  free(verified_psi_mod);
  free(verified_psi_rped);
  free(verified_psi_sch);
  group_elem_free(ver_public);

  // Refresh Party's values
  scalar_add(party->secret_x, party->secret_x, sum_received_reshares, party->sid->ec_order);
  scalar_free(sum_received_reshares);

  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    for (uint64_t k = 0; k > party->num_parties; ++k) group_operation(party->public_X[k], NULL, party->parties[i]->refresh_data->reshare_public_X_j[k], NULL, party->sid->ec);

    party->paillier_pub[i] = paillier_encryption_copy_public(party->parties[i]->refresh_data->paillier_priv);
    party->rped_pub[i] = ring_pedersen_copy_public(party->parties[i]->refresh_data->rped_priv);
  }

  if (party->paillier_priv) paillier_encryption_free_keys(party->paillier_priv, NULL);
  party->paillier_priv = paillier_encryption_duplicate_key(reda->paillier_priv);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;
  
  printf("# Final. Party %lu stores fresh (secret x_i, all public X, N_i, s_i, t_i).\t%lu B, %lu ms\n", party->id, 
    party->num_parties * GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES + party->num_parties*3*PAILLIER_MODULUS_BYTES, time_diff);
  printf("fresh_x_%lu = ", party->index); printBIGNUM("", party->secret_x, "\n");
  for (__UINT64_TYPE__ i = 0; i < party->num_parties; ++i) 
  {
    printf("X_%lu = ", i); printECPOINT("secp2561k.Point(", party->public_X[i], party->sid->ec, ")\n", 1);
    printf("N_%lu = ", i); printBIGNUM("", party->rped_pub[i]->N, "\n");
    printf("s_%lu = ", i); printBIGNUM("", party->rped_pub[i]->s, "\n");
    printf("t_%lu = ", i); printBIGNUM("", party->rped_pub[i]->t, "\n");
  }
}
