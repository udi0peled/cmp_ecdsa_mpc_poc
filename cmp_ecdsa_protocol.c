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

/********************************************
 *
 *   Party Context for Protocol Execution
 * 
 ********************************************/

void cmp_set_sid_hash(cmp_party_t *party)
{
  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, party->sid, sizeof(hash_chunk));
  SHA512_Update(&sha_ctx, party->srid, sizeof(hash_chunk));

  uint8_t temp_bytes[PAILLIER_MODULUS_BYTES];           // Enough for uint64_t and group_element

  group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, party->ec_gen, party->ec);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(temp_bytes,GROUP_ORDER_BYTES, party->ec_order);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ORDER_BYTES);

  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    SHA512_Update(&sha_ctx, &party->parties_ids[i], sizeof(uint64_t));
    if (party->public_X[i])
    {
      group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, party->public_X[i], party->ec);
      SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
    }
    if (party->paillier_pub[i] && party->rped_pub[i])
    {
      scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, party->paillier_pub[i]->N);
      SHA512_Update(&sha_ctx, temp_bytes, PAILLIER_MODULUS_BYTES);
      scalar_to_bytes(temp_bytes, RING_PED_MODULUS_BYTES, party->rped_pub[i]->N);
      SHA512_Update(&sha_ctx, temp_bytes, RING_PED_MODULUS_BYTES);
      scalar_to_bytes(temp_bytes, RING_PED_MODULUS_BYTES, party->rped_pub[i]->s);
      SHA512_Update(&sha_ctx, temp_bytes, RING_PED_MODULUS_BYTES);
      scalar_to_bytes(temp_bytes, RING_PED_MODULUS_BYTES, party->rped_pub[i]->t);
      SHA512_Update(&sha_ctx, temp_bytes, RING_PED_MODULUS_BYTES);
    }
  }

  SHA512_Final(party->sid_hash, &sha_ctx);
}

void cmp_party_new (cmp_party_t **parties, uint64_t num_parties, const uint64_t *parties_ids, uint64_t index, const hash_chunk sid)
{
  cmp_party_t *party = malloc(sizeof(*party));
  
  parties[index] = party;
  party->parties = parties;
  
  party->id = parties_ids[index];
  party->index = index;
  party->num_parties = num_parties;
  party->parties_ids = calloc(num_parties, sizeof(uint64_t));
  
  party->secret_x = scalar_new();
  party->public_X = calloc(num_parties, sizeof(gr_elem_t));

  party->paillier_priv = NULL;
  party->paillier_pub  = calloc(num_parties, sizeof(paillier_public_key_t *));
  party->rped_pub      = calloc(num_parties, sizeof(ring_pedersen_public_t *));
  
  party->ec       = ec_group_new();
  party->ec_gen   = ec_group_generator(party->ec);
  party->ec_order = ec_group_order(party->ec);

  memcpy(party->sid, sid, sizeof(hash_chunk));
  memset(party->srid, 0x00, sizeof(hash_chunk));
  for (uint64_t i = 0; i < num_parties; ++i)
  {
    party->parties_ids[i]  = parties_ids[i];
    party->public_X[i]     = NULL;
    party->paillier_pub[i] = NULL;
    party->rped_pub[i]     = NULL; 
  }
  cmp_set_sid_hash(party);

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
  ec_group_free(party->ec);
  free(party->paillier_pub);
  free(party->parties_ids);
  free(party->rped_pub);
  free(party->public_X);
  free(party);
}

/*********************** 
 * 
 *    Key Generation
 * 
 ***********************/

void cmp_key_generation_init(cmp_party_t *party)
{
  cmp_key_generation_t *kgd = malloc(sizeof(*party->key_generation_data));
  party->key_generation_data = kgd;

  kgd->secret_x = scalar_new();
  kgd->public_X = group_elem_new(party->ec);

  kgd->tau = scalar_new();
  kgd->psi = zkp_schnorr_new();
  kgd->aux = zkp_aux_info_new(2*sizeof(hash_chunk) + sizeof(uint64_t), NULL, 0); // prepeare for (sid_hash, i, srid)

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

void cmp_key_generation_round_1_commit(hash_chunk V, const hash_chunk sid_hash, uint64_t party_id, const cmp_party_t *party)
{
  cmp_key_generation_t *kgd = party->key_generation_data;

  uint8_t temp_bytes[GROUP_ELEMENT_BYTES];

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, sid_hash, sizeof(hash_chunk));
  SHA512_Update(&sha_ctx, &party_id, sizeof(uint64_t));
  SHA512_Update(&sha_ctx, kgd->srid, sizeof(hash_chunk));
  
  group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, kgd->public_X, party->ec);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, kgd->psi->proof.A, party->ec);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  SHA512_Update(&sha_ctx, kgd->u, sizeof(hash_chunk));
  SHA512_Final(V, &sha_ctx);
}

void  cmp_key_generation_round_1_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_key_generation_t *kgd = party->key_generation_data;

  scalar_sample_in_range(kgd->secret_x, party->ec_order, 0);
  group_operation(kgd->public_X, NULL, party->ec_gen, kgd->secret_x, party->ec);

  kgd->psi->public.G = party->ec;
  kgd->psi->public.g = party->ec_gen;
  zkp_schnorr_commit(kgd->psi, kgd->tau);

  cmp_sample_bytes(kgd->srid, sizeof(hash_chunk));
  cmp_sample_bytes(kgd->u, sizeof(hash_chunk));
  cmp_key_generation_round_1_commit(kgd->V, party->sid, party->id, party);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;

  printf("# Round 1. Party %lu broadcasts (sid, i, V_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(uint64_t) + sizeof(hash_chunk), time_diff);
  printHexBytes("sid_hash = ", party->sid_hash, sizeof(hash_chunk), "\n");
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
  printf("X_%lu = ", party->index); printECPOINT("secp256k1.Point(", kgd->public_X, party->ec, ")\n", 1);
  printf("A_%lu = ", party->index); printECPOINT("secp256k1.Point(", kgd->psi->proof.A, party->ec, ")\n", 1);
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
  memcpy(party->srid, kgd->srid, sizeof(hash_chunk));
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    // Verify commited V_i
    cmp_key_generation_round_1_commit(ver_data, party->sid, party->parties_ids[j], party->parties[j]);
    verified_decomm[j] = memcmp(ver_data, party->parties[j]->key_generation_data->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment -- ToDo: expand to identification of malicious party
    verified_echo[j] = memcmp(kgd->echo_broadcast, party->parties[j]->key_generation_data->echo_broadcast, sizeof(hash_chunk)) == 0;

    // Set srid as xor of all party's srid_i
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) party->srid[pos] ^= party->parties[j]->key_generation_data->srid[pos];
  }

  for (uint64_t j = 0; j < party->num_parties; ++j){
    if (j == party->index) continue;
    if (verified_decomm[j] != 1) printf("%sParty %lu: decommitment of V_i from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_echo[j] != 1)   printf("%sParty %lu: received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
  }

  free(verified_decomm);
  free(verified_echo);

  // Aux Info (ssid, i, srid)
  uint64_t aux_pos = 0;
  zkp_aux_info_update(kgd->aux, aux_pos, party->sid_hash, sizeof(hash_chunk));    aux_pos += sizeof(hash_chunk);
  zkp_aux_info_update(kgd->aux, aux_pos, &party->id, sizeof(uint64_t));           aux_pos += sizeof(uint64_t);
  zkp_aux_info_update(kgd->aux, aux_pos, party->srid, sizeof(hash_chunk));        aux_pos += sizeof(hash_chunk);
  assert(kgd->aux->info_len == aux_pos);

  // Set Schnorr ZKP public claim and secret, then prove
  kgd->psi->public.X = kgd->public_X;
  kgd->psi->secret.x = kgd->secret_x;
  zkp_schnorr_prove(kgd->psi, kgd->aux, kgd->tau);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;
  
  printf("# Round 3. Party %lu publishes (sid, i, psi_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(uint64_t) + ZKP_SCHNORR_PROOF_BYTES, time_diff);
  printHexBytes("combined srid = ", party->srid, sizeof(hash_chunk), "\n");
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
    zkp_aux_info_update(kgd->aux, sizeof(hash_chunk), &party->parties_ids[j], sizeof(uint64_t));     // Update i to commiting player
    verified_psi[j] = zkp_schnorr_verify(party->parties[j]->key_generation_data->psi, kgd->aux)
      && group_elem_equal(party->parties[j]->key_generation_data->psi->proof.A, party->parties[j]->key_generation_data->psi->proof.A, party->ec);      // Check A's of rounds 2 and 3
  }

  for (uint64_t j = 0; j < party->num_parties; ++j){
    if (j == party->index) continue;
    if (verified_psi[j] != 1) printf("%sParty %lu: schnorr zkp (psi) failed verification from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
  }
  
  free(verified_psi);

  // Set party's values, and update sid_hash to include srid and public_X
  scalar_copy(party->secret_x, kgd->secret_x);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (!party->public_X[j]) party->public_X[j] = group_elem_new(party->ec);
    group_elem_copy(party->public_X[j], party->parties[j]->key_generation_data->public_X);
  }
  cmp_set_sid_hash(party);
  
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
  reda->aux      = zkp_aux_info_new(2*sizeof(hash_chunk) + sizeof(uint64_t), NULL, 0);   // prepare for (sid, i, rho)
  
  reda->reshare_secret_x_j = calloc(party->num_parties, sizeof(scalar_t));
  reda->encrypted_reshare_j = calloc(party->num_parties, sizeof(scalar_t));
  reda->reshare_public_X_j = calloc(party->num_parties, sizeof(gr_elem_t));

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    reda->tau[j]                 = scalar_new();
    reda->reshare_secret_x_j[j]  = scalar_new();
    reda->encrypted_reshare_j[j] = scalar_new();
    reda->reshare_public_X_j[j]  = group_elem_new(party->ec);
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

void cmp_refresh_aux_info_round_1_commit(hash_chunk V, const hash_chunk sid_hash, uint64_t party_id, const cmp_party_t *party)
{
  cmp_refresh_aux_info_t *reda = party->refresh_data;

  uint8_t temp_bytes[PAILLIER_MODULUS_BYTES];     // Enough also for GROUP_ELEMENT_BYTES

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, sid_hash, sizeof(hash_chunk));
  SHA512_Update(&sha_ctx, &party_id, sizeof(uint64_t));

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, reda->reshare_public_X_j[j], party->ec);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  }

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    group_elem_to_bytes(temp_bytes, GROUP_ELEMENT_BYTES, reda->psi_sch[j]->proof.A, party->ec);
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
  scalar_set_word(reda->reshare_secret_x_j[party->index], 0);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    // Also initialize relevant zkp
    reda->psi_sch[j]->public.G = party->ec;
    reda->psi_sch[j]->public.g = party->ec_gen;
    zkp_schnorr_commit(reda->psi_sch[j], reda->tau[j]);

    // Dont choose your own values, only later if needed
    if (j == party->index) continue; 

    scalar_sample_in_range(reda->reshare_secret_x_j[j], party->ec_order, 0);
    group_operation(reda->reshare_public_X_j[j], NULL, party->ec_gen, reda->reshare_secret_x_j[j], party->ec);
    scalar_sub(reda->reshare_secret_x_j[party->index], reda->reshare_secret_x_j[party->index], reda->reshare_secret_x_j[j], party->ec_order);
  }
  group_operation(reda->reshare_public_X_j[party->index], NULL, party->ec_gen, reda->reshare_secret_x_j[party->index], party->ec);

  cmp_sample_bytes(reda->rho, sizeof(hash_chunk));
  cmp_sample_bytes(reda->u, sizeof(hash_chunk));
  cmp_refresh_aux_info_round_1_commit(reda->V, party->sid, party->id, party);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;

  printf("# Round 1. Party %lu broadcasts (sid, i, V_i).\t%lu B, %lu ms\n", party->id, 2*sizeof(hash_chunk)+sizeof(uint64_t), time_diff);
  printHexBytes("sid_hash = ", party->sid_hash, sizeof(hash_chunk), "\n");
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
    party->id, 2*sizeof(uint64_t) + party->num_parties*2*GROUP_ELEMENT_BYTES + 3*PAILLIER_MODULUS_BYTES + 3*sizeof(hash_chunk), reda->prime_time, time_diff);
  
  printf("echo_broadcast_%lu = ", party->index); printHexBytes("echo_broadcast = ", reda->echo_broadcast, sizeof(hash_chunk), "\n");
  printf("rho_%lu = ", party->index); printHexBytes("", reda->rho, sizeof(hash_chunk), "\n");
  printf("u_%lu = ", party->index); printHexBytes("", reda->u, sizeof(hash_chunk), "\n");
  printf("N_%lu = ", party->index); printBIGNUM("", reda->rped_priv->pub.N, "\n");
  printf("s_%lu = ", party->index); printBIGNUM("", reda->rped_priv->pub.s, "\n");
  printf("t_%lu = ", party->index); printBIGNUM("", reda->rped_priv->pub.t, "\n");

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    printf("X_%lue%lu = ", party->index, j); printECPOINT("secp256k1.Point(", reda->reshare_public_X_j[j], party->ec, ")\n", 1);
    printf("A_%lue%lu = ", party->index, j); printECPOINT("secp256k1.Point(", reda->psi_sch[j]->proof.A, party->ec, ")\n", 1);
  }
}

void  cmp_refresh_aux_info_round_3_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_aux_info_t *reda = party->refresh_data;
  
  gr_elem_t combined_public = group_elem_new(party->ec);

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
    group_operation(combined_public, NULL, NULL, NULL, party->ec);
    for (uint64_t k = 0; k < party->num_parties; ++k) {
      group_operation(combined_public, combined_public, party->parties[j]->refresh_data->reshare_public_X_j[k], NULL, party->ec);
    }
    verified_public_shares[j] = group_elem_is_ident(combined_public, party->ec) == 1;

    // Verify commited V_i
    cmp_refresh_aux_info_round_1_commit(ver_data, party->sid, party->parties_ids[j], party->parties[j]);
    verified_decomm[j] = memcmp(ver_data, party->parties[j]->refresh_data->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment -- ToDo: expand to identification of malicious party
    verified_echo[j] = memcmp(reda->echo_broadcast, party->parties[j]->refresh_data->echo_broadcast, sizeof(hash_chunk)) == 0;

    // Set combined rho as xor of all party's rho_i
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) reda->combined_rho[pos] ^= party->parties[j]->refresh_data->rho[pos];
  }

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    if (verified_modulus_size[j] != 1)  printf("%sParty %lu: N_i bitlength from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_public_shares[j] != 1) printf("%sParty %lu: invalid X_j_k sharing from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_decomm[j] != 1)        printf("%sParty %lu: decommitment of V_i from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_echo[j] != 1)          printf("%sParty %lu: received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
  }

  free(verified_modulus_size);
  free(verified_public_shares);
  free(verified_decomm);
  free(verified_echo);
  group_elem_free(combined_public);

    // Aux Info for ZKP (ssid, i, combined rho)
  uint64_t aux_pos = 0;
  zkp_aux_info_update(reda->aux, aux_pos, party->sid_hash, sizeof(hash_chunk));         aux_pos += sizeof(hash_chunk);
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
  for (uint64_t j = 0; j < party->num_parties; ++j)
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
  gr_elem_t ver_public = group_elem_new(party->ec);
  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  { 
    // Decrypt and verify reshare secret vs public   
    paillier_encryption_decrypt(received_reshare, party->parties[j]->refresh_data->encrypted_reshare_j[party->index], reda->paillier_priv);     // TODO: reduce MODULU q!!!
    scalar_add(sum_received_reshares, sum_received_reshares, received_reshare, party->ec_order);
    group_operation(ver_public, NULL, party->ec_gen, received_reshare, party->ec);
    verified_reshare[j] = group_elem_equal(ver_public, party->parties[j]->refresh_data->reshare_public_X_j[party->index], party->ec) == 1;

    if (j == party->index) continue; 

    zkp_aux_info_update(reda->aux, sizeof(hash_chunk), &party->parties_ids[j], sizeof(uint64_t));                  // Update i to commiting player
    verified_psi_mod[j] = zkp_paillier_blum_verify(party->parties[j]->refresh_data->psi_mod, reda->aux) == 1;
    verified_psi_rped[j] = zkp_ring_pedersen_param_verify(party->parties[j]->refresh_data->psi_rped, reda->aux) == 1;

    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      verified_psi_sch[k + party->num_parties*j] = (zkp_schnorr_verify(party->parties[j]->refresh_data->psi_sch[k], reda->aux) == 1)
       && (group_elem_equal(party->parties[j]->refresh_data->psi_sch[k]->proof.A, party->parties[j]->refresh_data->psi_sch[k]->proof.A, party->ec) == 1);      // Check A's of rounds 2 and 3
    }
  }
  scalar_free(received_reshare);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    if (verified_reshare[j] != 1)  printf("%sParty %lu: Public reshare inconsistent from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_psi_mod[j] != 1)  printf("%sParty %lu: Paillier-Blum ZKP failed verification from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_psi_rped[j] != 1) printf("%sParty %lu: Ring-Pedersen ZKP failed verification from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      if (verified_psi_sch[k + party->num_parties*j] != 1) printf("%sParty %lu: Schnorr ZKP failed verification from Party %lu for Party %lu\n",ERR_STR, party->id, party->parties_ids[j], party->parties_ids[k]);
    }
  }

  free(verified_reshare);
  free(verified_psi_mod);
  free(verified_psi_rped);
  free(verified_psi_sch);
  group_elem_free(ver_public);

  // Refresh Party's values
  scalar_add(party->secret_x, party->secret_x, sum_received_reshares, party->ec_order);
  scalar_free(sum_received_reshares);

  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    for (uint64_t k = 0; k > party->num_parties; ++k) group_operation(party->public_X[k], NULL, party->parties[i]->refresh_data->reshare_public_X_j[k], NULL, party->ec);

    party->paillier_pub[i] = paillier_encryption_copy_public(party->parties[i]->refresh_data->paillier_priv);
    party->rped_pub[i] = ring_pedersen_copy_public(party->parties[i]->refresh_data->rped_priv);
  }

  if (party->paillier_priv) paillier_encryption_free_keys(party->paillier_priv, NULL);
  party->paillier_priv = paillier_encryption_duplicate_key(reda->paillier_priv);

  cmp_set_sid_hash(party);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;
  
  printf("# Final. Party %lu stores fresh (secret x_i, all public X, N_i, s_i, t_i).\t%lu B, %lu ms\n", party->id, 
    party->num_parties * GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES + party->num_parties*3*PAILLIER_MODULUS_BYTES, time_diff);
  printf("fresh_x_%lu = ", party->index); printBIGNUM("", party->secret_x, "\n");
  for (__UINT64_TYPE__ i = 0; i < party->num_parties; ++i) 
  {
    printf("X_%lu = ", i); printECPOINT("secp2561k.Point(", party->public_X[i], party->ec, ")\n", 1);
    printf("N_%lu = ", i); printBIGNUM("", party->rped_pub[i]->N, "\n");
    printf("s_%lu = ", i); printBIGNUM("", party->rped_pub[i]->s, "\n");
    printf("t_%lu = ", i); printBIGNUM("", party->rped_pub[i]->t, "\n");
  }
}

/******************************************** 
 * 
 *   Pre-Signing
 * 
 ********************************************/

void cmp_presigning_init(cmp_party_t *party)
{
  cmp_presigning_t *preda = malloc(sizeof(*preda));
  party->presigning_data = preda;

  preda->G     = scalar_new();
  preda->K     = scalar_new();
  preda->k     = scalar_new();
  preda->gamma = scalar_new();
  preda->rho   = scalar_new();
  preda->nu    = scalar_new();
  preda->delta = scalar_new();

  preda->Delta          = group_elem_new(party->ec);
  preda->Gamma          = group_elem_new(party->ec);
  preda->combined_Gamma = group_elem_new(party->ec);

  preda->alpha_j    = calloc(party->num_parties, sizeof(scalar_t));
  preda->beta_j     = calloc(party->num_parties, sizeof(scalar_t));
  preda->alphahat_j = calloc(party->num_parties, sizeof(scalar_t));
  preda->betahat_j  = calloc(party->num_parties, sizeof(scalar_t));
  preda->D_j        = calloc(party->num_parties, sizeof(scalar_t));
  preda->F_j        = calloc(party->num_parties, sizeof(scalar_t));
  preda->Dhat_j     = calloc(party->num_parties, sizeof(scalar_t));
  preda->Fhat_j     = calloc(party->num_parties, sizeof(scalar_t));

  preda->psi_enc  = calloc(party->num_parties, sizeof(zkp_encryption_in_range_t));
  preda->psi_affp = calloc(party->num_parties, sizeof(zkp_operation_paillier_commitment_range_t));
  preda->psi_affg = calloc(party->num_parties, sizeof(zkp_operation_group_commitment_range_t));
  preda->psi_log  = calloc(party->num_parties, sizeof(zkp_group_vs_paillier_range_t));

  preda->aux      = zkp_aux_info_new(sizeof(hash_chunk) + sizeof(uint64_t), NULL, 0);      // Prepate for (sid_hash, i);
  
  for (uint64_t j = 0; j < party->num_parties; ++j){
    preda->alpha_j[j]    = scalar_new();
    preda->beta_j[j]     = scalar_new();
    preda->alphahat_j[j] = scalar_new();
    preda->betahat_j[j]  = scalar_new();
    preda->D_j[j]        = scalar_new();
    preda->F_j[j]        = scalar_new();
    preda->Dhat_j[j]     = scalar_new();
    preda->Fhat_j[j]     = scalar_new();

    if (j == party->index) continue;

    preda->psi_enc [j] = zkp_encryption_in_range_new();
    preda->psi_affp[j] = zkp_operation_paillier_commitment_range_new();
    preda->psi_affg[j] = zkp_operation_group_commitment_range_new();
    preda->psi_log [j] = zkp_group_vs_paillier_range_new();
  }

  preda->run_time = 0;
}

void cmp_presigning_clean(cmp_party_t *party)
{
  cmp_presigning_t *preda = party->presigning_data;

  scalar_free(preda->G    );
  scalar_free(preda->K    );
  scalar_free(preda->k    );
  scalar_free(preda->gamma);
  scalar_free(preda->rho  );
  scalar_free(preda->nu   );
  scalar_free(preda->delta);

  group_elem_free(preda->Delta         );
  group_elem_free(preda->Gamma         );
  group_elem_free(preda->combined_Gamma);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    scalar_free(preda->alpha_j[j]);
    scalar_free(preda->beta_j[j] );
    scalar_free(preda->alphahat_j[j]);
    scalar_free(preda->betahat_j[j] );
    scalar_free(preda->D_j[j]    );
    scalar_free(preda->F_j[j]    );
    scalar_free(preda->Dhat_j[j] );
    scalar_free(preda->Fhat_j[j] );

    if (j == party->index) continue;

    zkp_encryption_in_range_free(preda->psi_enc [j]);
    zkp_operation_paillier_commitment_range_free(preda->psi_affp[j]);
    zkp_operation_group_commitment_range_free(preda->psi_affg[j]);
    zkp_group_vs_paillier_range_free(preda->psi_log [j]);
  }

  zkp_aux_info_free(preda->aux);

  free(preda->alphahat_j);
  free(preda->betahat_j );
  free(preda->alpha_j);
  free(preda->beta_j );
  free(preda->D_j    );
  free(preda->F_j    );
  free(preda->Dhat_j );
  free(preda->Fhat_j );

  free(preda->psi_enc );
  free(preda->psi_affp);
  free(preda->psi_affg);
  free(preda->psi_log );
  free(preda);
}


void cmp_presigning_round_1_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_presigning_t *preda = party->presigning_data;

  paillier_encryption_sample(preda->rho, &party->paillier_priv->pub);
  scalar_sample_in_range(preda->k, party->ec_order, 0);
  paillier_encryption_encrypt(preda->K, preda->k, preda->rho, &party->paillier_priv->pub);

  paillier_encryption_sample(preda->nu, &party->paillier_priv->pub);
  scalar_sample_in_range(preda->gamma, party->ec_order, 0);
  paillier_encryption_encrypt(preda->G, preda->gamma, preda->nu, &party->paillier_priv->pub);

  uint64_t aux_pos = 0;
  zkp_aux_info_update(preda->aux, aux_pos, party->sid_hash, sizeof(hash_chunk));    aux_pos += sizeof(hash_chunk);
  zkp_aux_info_update(preda->aux, aux_pos, &party->id, sizeof(uint64_t));           aux_pos += sizeof(uint64_t);
  assert(preda->aux->info_len == aux_pos);

  for (uint64_t j = 0; j < party->num_parties; ++j) 
  {
    if (j == party->index) continue;

    preda->psi_enc[j]->public.G = party->ec;
    preda->psi_enc[j]->public.K = preda->K;
    preda->psi_enc[j]->public.paillier_pub = &party->paillier_priv->pub;
    preda->psi_enc[j]->public.rped_pub = party->rped_pub[party->index];
    preda->psi_enc[j]->secret.k = preda->k;
    preda->psi_enc[j]->secret.rho = preda->rho;
    zkp_encryption_in_range_prove(preda->psi_enc[j], preda->aux);
  }
  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  preda->run_time += time_diff;

  printf("# Round 1. Party %lu broadcasts (sid, i, K_i, G_i). Send (sid, i, psi_enc_j) to each Party j.\t%lu B, %lu ms\n", party->id,
    2*sizeof(hash_chunk) + sizeof(uint64_t) + 4*PAILLIER_MODULUS_BYTES + (party->num_parties-1) * ZKP_ENCRYPTION_IN_RANGE_PROOF_BYTES, time_diff);
  printHexBytes("sid_hash = ", party->sid_hash, sizeof(hash_chunk), "\n");
  printf("k_%lu = ", party->index); printBIGNUM("", preda->k, "\n");
  printf("gamma_%lu = ", party->index); printBIGNUM("", preda->gamma, "\n");
}


void  cmp_presigning_round_2_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_presigning_t *preda = party->presigning_data;

  int *verified_psi_enc = calloc(party->num_parties, sizeof(int));

  // Echo broadcast - Send hash of all K_j,G_j
  uint8_t temp_bytes[PAILLIER_MODULUS_BYTES];
  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, party->parties[i]->presigning_data->K);
    SHA512_Update(&sha_ctx, temp_bytes, PAILLIER_MODULUS_BYTES);
    scalar_to_bytes(temp_bytes, PAILLIER_MODULUS_BYTES, party->parties[i]->presigning_data->G);
    SHA512_Update(&sha_ctx, temp_bytes, PAILLIER_MODULUS_BYTES);
  }
  SHA512_Final(preda->echo_broadcast, &sha_ctx);

  // Verify psi_enc received
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    zkp_aux_info_update(preda->aux, sizeof(hash_chunk), &party->parties_ids[j], sizeof(uint64_t));
    verified_psi_enc[j] = zkp_encryption_in_range_verify(party->parties[j]->presigning_data->psi_enc[party->index], preda->aux);
    if (verified_psi_enc[j] != 1)  printf("%sParty %lu: failed verification of psi_enc from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
  }
  free(verified_psi_enc);

  group_operation(preda->Gamma, NULL, party->ec_gen, preda->gamma, party->ec);

  uint64_t aux_pos = 0;
  zkp_aux_info_update(preda->aux, aux_pos, party->sid_hash, sizeof(hash_chunk));    aux_pos += sizeof(hash_chunk);
  zkp_aux_info_update(preda->aux, aux_pos, &party->id, sizeof(uint64_t));           aux_pos += sizeof(uint64_t);
  assert(preda->aux->info_len == aux_pos);

  // Executing MtA with relevant ZKP

  scalar_t r          = scalar_new();
  scalar_t s          = scalar_new();
  scalar_t temp_enc   = scalar_new();
  scalar_t neg_beta   = scalar_new();
  scalar_t beta_range = scalar_new();

  scalar_set_power_of_2(beta_range, 8*CALIGRAPHIC_J_ZKP_RANGE_BYTES);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    
    // Create ZKP Paillier homomorphic operation against Paillier commitment

    scalar_sample_in_range(preda->beta_j[j], beta_range, 0);
    scalar_make_plus_minus(preda->beta_j[j], beta_range);
    paillier_encryption_sample(r, &party->paillier_priv->pub);
    paillier_encryption_encrypt(preda->F_j[j], preda->beta_j[j], r, &party->paillier_priv->pub);

    scalar_negate(neg_beta, preda->beta_j[j]);
    paillier_encryption_sample(s, &party->paillier_priv->pub);
    paillier_encryption_encrypt(temp_enc, neg_beta, s, party->paillier_pub[j]);
    paillier_encryption_homomorphic(preda->D_j[j], party->parties[j]->presigning_data->K, preda->gamma, temp_enc, party->paillier_pub[j]);

    preda->psi_affp[j]->public.G = party->ec;
    preda->psi_affp[j]->public.rped_pub = party->rped_pub[j];
    preda->psi_affp[j]->public.paillier_pub_0 = party->paillier_pub[j];
    preda->psi_affp[j]->public.paillier_pub_1 = &party->paillier_priv->pub;
    preda->psi_affp[j]->public.C = party->parties[j]->presigning_data->K;
    preda->psi_affp[j]->public.D = preda->D_j[j];
    preda->psi_affp[j]->public.X = preda->G;
    preda->psi_affp[j]->public.Y = preda->F_j[j];       // TODO: maybe should be temp_enc check ZKP if againg \beta or -\beta?
    zkp_operation_paillier_commitment_range_prove(preda->psi_affp[j], preda->aux);
  }

  scalar_free(beta_range);
  scalar_free(neg_beta);
  scalar_free(temp_enc);
  scalar_free(r);
  scalar_free(s);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  preda->run_time += time_diff;

  // printf("# Round 2. Party %lu publishes (sid, i, X_i^{1...n}, A_i^{1...n}, Paillier N_i, s_i, t_i, rho_i, u_i, echo_broadcast).\t%lu B, %lu ms (gen N_i) + %lu ms (rest)\n", 
  //   party->id, 2*sizeof(uint64_t) + party->num_parties*2*GROUP_ELEMENT_BYTES + 3*PAILLIER_MODULUS_BYTES + 3*sizeof(hash_chunk), reda->prime_time, time_diff);
  
  // printf("echo_broadcast_%lu = ", party->index); printHexBytes("echo_broadcast = ", reda->echo_broadcast, sizeof(hash_chunk), "\n");
  // printf("rho_%lu = ", party->index); printHexBytes("", reda->rho, sizeof(hash_chunk), "\n");
  // printf("u_%lu = ", party->index); printHexBytes("", reda->u, sizeof(hash_chunk), "\n");
  // printf("N_%lu = ", party->index); printBIGNUM("", reda->rped_priv->pub.N, "\n");
  // printf("s_%lu = ", party->index); printBIGNUM("", reda->rped_priv->pub.s, "\n");
  // printf("t_%lu = ", party->index); printBIGNUM("", reda->rped_priv->pub.t, "\n");

  // for (uint64_t j = 0; j < party->num_parties; ++j)
  // {
  //   printf("X_%lue%lu = ", party->index, j); printECPOINT("secp256k1.Point(", reda->reshare_public_X_j[j], party->ec, ")\n", 1);
  //   printf("A_%lue%lu = ", party->index, j); printECPOINT("secp256k1.Point(", reda->psi_sch[j]->proof.A, party->ec, ")\n", 1);
  // }
}
/*
void  cmp_presigning_round_3_exec (cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_presigning_t *reda = party->refresh_data;
  
  gr_elem_t combined_public = group_elem_new(party->ec);

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
    group_operation(combined_public, NULL, NULL, NULL, party->ec);
    for (uint64_t k = 0; k < party->num_parties; ++k) {
      group_operation(combined_public, combined_public, party->parties[j]->refresh_data->reshare_public_X_j[k], NULL, party->ec);
    }
    verified_public_shares[j] = group_elem_is_ident(combined_public, party->ec) == 1;

    // Verify commited V_i
    cmp_presigning_round_1_commit(ver_data, party->sid, party->parties_ids[j], party->parties[j]);
    verified_decomm[j] = memcmp(ver_data, party->parties[j]->refresh_data->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment -- ToDo: expand to identification of malicious party
    verified_echo[j] = memcmp(reda->echo_broadcast, party->parties[j]->refresh_data->echo_broadcast, sizeof(hash_chunk)) == 0;

    // Set combined rho as xor of all party's rho_i
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) reda->combined_rho[pos] ^= party->parties[j]->refresh_data->rho[pos];
  }

  for (uint8_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    if (verified_modulus_size[j] != 1)  printf("%sParty %lu: N_i bitlength from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_public_shares[j] != 1) printf("%sParty %lu: invalid X_j_k sharing from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_decomm[j] != 1)        printf("%sParty %lu: decommitment of V_i from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_echo[j] != 1)          printf("%sParty %lu: received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
  }

  free(verified_modulus_size);
  free(verified_public_shares);
  free(verified_decomm);
  free(verified_echo);
  group_elem_free(combined_public);

    // Aux Info for ZKP (ssid, i, combined rho)
  uint64_t aux_pos = 0;
  zkp_aux_info_update(reda->aux, aux_pos, party->sid_hash, sizeof(hash_chunk));         aux_pos += sizeof(hash_chunk);
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

void cmp_presigning_final_exec(cmp_party_t *party)
{
  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_presigning_t *reda = party->refresh_data;

  int *verified_reshare  = calloc(party->num_parties, sizeof(int));
  int *verified_psi_mod  = calloc(party->num_parties, sizeof(int));
  int *verified_psi_rped = calloc(party->num_parties, sizeof(int));
  int *verified_psi_sch  = calloc(party->num_parties*party->num_parties, sizeof(int));

  // Verify all Schnorr ZKP and values received from parties  

  scalar_t received_reshare = scalar_new();
  scalar_t sum_received_reshares = scalar_new();
  gr_elem_t ver_public = group_elem_new(party->ec);
  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  { 
    // Decrypt and verify reshare secret vs public   
    paillier_encryption_decrypt(received_reshare, party->parties[j]->refresh_data->encrypted_reshare_j[party->index], reda->paillier_priv);     // TODO: reduce MODULU q!!!
    scalar_add(sum_received_reshares, sum_received_reshares, received_reshare, party->ec_order);
    group_operation(ver_public, NULL, party->ec_gen, received_reshare, party->ec);
    verified_reshare[j] = group_elem_equal(ver_public, party->parties[j]->refresh_data->reshare_public_X_j[party->index], party->ec) == 1;

    if (j == party->index) continue; 

    zkp_aux_info_update(reda->aux, sizeof(hash_chunk), &party->parties_ids[j], sizeof(uint64_t));                  // Update i to commiting player
    verified_psi_mod[j] = zkp_paillier_blum_verify(party->parties[j]->refresh_data->psi_mod, reda->aux) == 1;
    verified_psi_rped[j] = zkp_ring_pedersen_param_verify(party->parties[j]->refresh_data->psi_rped, reda->aux) == 1;

    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      verified_psi_sch[k + party->num_parties*j] = (zkp_schnorr_verify(party->parties[j]->refresh_data->psi_sch[k], reda->aux) == 1)
       && (group_elem_equal(party->parties[j]->refresh_data->psi_sch[k]->proof.A, party->parties[j]->refresh_data->psi_sch[k]->proof.A, party->ec) == 1);      // Check A's of rounds 2 and 3
    }
  }
  scalar_free(received_reshare);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    if (verified_reshare[j] != 1)  printf("%sParty %lu: Public reshare inconsistent from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_psi_mod[j] != 1)  printf("%sParty %lu: Paillier-Blum ZKP failed verification from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    if (verified_psi_rped[j] != 1) printf("%sParty %lu: Ring-Pedersen ZKP failed verification from Party %lu\n",ERR_STR, party->id, party->parties_ids[j]);
    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      if (verified_psi_sch[k + party->num_parties*j] != 1) printf("%sParty %lu: Schnorr ZKP failed verification from Party %lu for Party %lu\n",ERR_STR, party->id, party->parties_ids[j], party->parties_ids[k]);
    }
  }

  free(verified_reshare);
  free(verified_psi_mod);
  free(verified_psi_rped);
  free(verified_psi_sch);
  group_elem_free(ver_public);

  // Refresh Party's values
  scalar_add(party->secret_x, party->secret_x, sum_received_reshares, party->ec_order);
  scalar_free(sum_received_reshares);

  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    for (uint64_t k = 0; k > party->num_parties; ++k) group_operation(party->public_X[k], NULL, party->parties[i]->refresh_data->reshare_public_X_j[k], NULL, party->ec);

    party->paillier_pub[i] = paillier_encryption_copy_public(party->parties[i]->refresh_data->paillier_priv);
    party->rped_pub[i] = ring_pedersen_copy_public(party->parties[i]->refresh_data->rped_priv);
  }

  if (party->paillier_priv) paillier_encryption_free_keys(party->paillier_priv, NULL);
  party->paillier_priv = paillier_encryption_duplicate_key(reda->paillier_priv);

  cmp_set_sid_hash(party);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;
  
  printf("# Final. Party %lu stores fresh (secret x_i, all public X, N_i, s_i, t_i).\t%lu B, %lu ms\n", party->id, 
    party->num_parties * GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES + party->num_parties*3*PAILLIER_MODULUS_BYTES, time_diff);
  printf("fresh_x_%lu = ", party->index); printBIGNUM("", party->secret_x, "\n");
  for (__UINT64_TYPE__ i = 0; i < party->num_parties; ++i) 
  {
    printf("X_%lu = ", i); printECPOINT("secp2561k.Point(", party->public_X[i], party->ec, ")\n", 1);
    printf("N_%lu = ", i); printBIGNUM("", party->rped_pub[i]->N, "\n");
    printf("s_%lu = ", i); printBIGNUM("", party->rped_pub[i]->s, "\n");
    printf("t_%lu = ", i); printBIGNUM("", party->rped_pub[i]->t, "\n");
  }
}
*/