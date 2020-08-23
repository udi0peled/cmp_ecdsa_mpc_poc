#include "common.h"
#include "cmp_ecdsa_protocol.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <semaphore.h>

#define ERR_STR "\nXXXXX ERROR XXXXX\n\n"
extern int PRINT_SECRETS;

/********************************************
 *
 *   Auxiliary Functions
 * 
 ********************************************/

#define COMM_CHNL_PATTERN "CHANNEL_%lu_to_%lu_round_%lu.dat"

void cmp_comm_send_bytes(uint64_t my_index, uint64_t to_index, uint64_t round, const uint8_t *bytes, uint64_t byte_len)
{
  char filename[sizeof(COMM_CHNL_PATTERN) + 8];
  sprintf(filename, COMM_CHNL_PATTERN, my_index, to_index, round);

  // Lock reader until finished sending/writing to file
  sem_t* semptr = sem_open(filename, O_CREAT, 0644, 0);

  int fd = open(filename, O_RDWR | O_CREAT, 0644);
  write(fd, bytes, byte_len);

  srand(time(0));
  sleep(rand() % 5 + 1);

  close(fd);
  sem_post(semptr);
  sem_close(semptr);
}

void cmp_comm_receive_bytes(uint64_t from_index, uint64_t my_index, uint64_t round, uint8_t *bytes, uint64_t byte_len)
{
  char filename[sizeof(COMM_CHNL_PATTERN) + 8];
  sprintf(filename, COMM_CHNL_PATTERN, from_index, my_index, round);

  // Wait until file is written by sender
  sem_t* semptr = sem_open(filename, O_CREAT, 0644, 0);
  sem_wait(semptr);

  int fd = open(filename, O_RDONLY, 0644);  
  read(fd, bytes, byte_len);
  close(fd);
  remove(filename);
  sem_close(semptr);
  sem_unlink(filename);
}

void cmp_void_to_bytes(uint8_t **to_bytes, const void *from_bytes, uint64_t byte_len, int move_to_end)
{
  if ((!to_bytes) || (!*to_bytes) || (!from_bytes)) return;
  memcpy(*to_bytes, from_bytes, byte_len);
  if (move_to_end) *to_bytes += byte_len;
}

void cmp_void_from_bytes(void *to_bytes, uint8_t **from_bytes, uint64_t byte_len, int move_to_end)
{
  if ((!from_bytes) || (!*from_bytes) || (!to_bytes)) return;
  memcpy(to_bytes, *from_bytes, byte_len);
  if (move_to_end) *from_bytes += byte_len;
}

void cmp_sample_bytes (uint8_t *rand_bytes, uint64_t byte_len)
{
  RAND_bytes(rand_bytes, byte_len);
}

/********************************************
 *
 *   Party Context for Protocol Execution
 * 
 ********************************************/

// Set sid hash from relevant existing party values (phases: 0/1/2 - init/keygen/refresh)
void cmp_set_sid_hash(cmp_party_t *party, int phase)
{
  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, party->sid, sizeof(hash_chunk));
  if ((phase == 1) || (phase == 2))
  {
    SHA512_Update(&sha_ctx, party->srid, sizeof(hash_chunk));
  }

  uint8_t *temp_bytes = malloc(PAILLIER_MODULUS_BYTES);           // Enough for uint64_t and group_element

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, party->ec_gen, party->ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(&temp_bytes,GROUP_ORDER_BYTES, party->ec_order, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ORDER_BYTES);

  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    SHA512_Update(&sha_ctx, &party->parties_ids[i], sizeof(uint64_t));
    if ((phase == 1) || (phase == 2))
    {
      group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, party->public_X[i], party->ec, 0);
      SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
    }

    if (phase == 2)
    {
      scalar_to_bytes(&temp_bytes, PAILLIER_MODULUS_BYTES, party->paillier_pub[i]->N, 0);
      SHA512_Update(&sha_ctx, temp_bytes, PAILLIER_MODULUS_BYTES);
      scalar_to_bytes(&temp_bytes, RING_PED_MODULUS_BYTES, party->rped_pub[i]->N, 0);
      SHA512_Update(&sha_ctx, temp_bytes, RING_PED_MODULUS_BYTES);
      scalar_to_bytes(&temp_bytes, RING_PED_MODULUS_BYTES, party->rped_pub[i]->s, 0);
      SHA512_Update(&sha_ctx, temp_bytes, RING_PED_MODULUS_BYTES);
      scalar_to_bytes(&temp_bytes, RING_PED_MODULUS_BYTES, party->rped_pub[i]->t, 0);
      SHA512_Update(&sha_ctx, temp_bytes, RING_PED_MODULUS_BYTES);
    }
  }
  free(temp_bytes);

  SHA512_Final(party->sid_hash, &sha_ctx);
}

cmp_party_t *cmp_party_new (uint64_t party_index, uint64_t num_parties, const uint64_t *parties_ids, const hash_chunk sid)
{
  cmp_party_t *party = malloc(sizeof(*party));
  
  //parties[index] = party;
  //party->parties = parties;
  
  party->id = parties_ids[party_index];
  party->index = party_index;
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

  party->R   = group_elem_new(party->ec);
  party->k   = scalar_new();
  party->chi = scalar_new();

  memcpy(party->sid, sid, sizeof(hash_chunk));
  //memset(party->srid, 0x00, sizeof(hash_chunk));

  party->paillier_priv = paillier_encryption_private_new();
  for (uint64_t i = 0; i < num_parties; ++i)
  {
    party->parties_ids[i]  = parties_ids[i];
    party->public_X[i]     = group_elem_new(party->ec);;
    party->paillier_pub[i] = paillier_encryption_public_new();
    party->rped_pub[i]     = ring_pedersen_public_new(); 
  }
  cmp_set_sid_hash(party, 0);

  party->key_generation_data = NULL;
  party->refresh_data = NULL;
  party->presign_data = NULL;

  return party;
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

  group_elem_free(party->R);
  scalar_free(party->k);
  scalar_free(party->chi);
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
  cmp_key_generation_data_t *kgd = malloc(sizeof(cmp_key_generation_data_t));
  party->key_generation_data = kgd;

  kgd->payload = calloc(party->num_parties, sizeof(cmp_key_generation_payload_t *));
  for (uint64_t j = 0; j < party->num_parties; ++j)
  { 
    kgd->payload[j] = malloc(sizeof(cmp_key_generation_payload_t));
    kgd->payload[j]->commited_A = group_elem_new(party->ec);
    kgd->payload[j]->public_X = group_elem_new(party->ec);
    kgd->payload[j]->psi_sch = zkp_schnorr_new();
  }

  kgd->secret_x = scalar_new();
  kgd->tau      = scalar_new();
  
  // Point to values stored in payload (to be sent)
  kgd->public_X       = kgd->payload[party->index]->public_X;
  kgd->commited_A     = kgd->payload[party->index]->commited_A;
  kgd->psi_sch        = kgd->payload[party->index]->psi_sch;
  kgd->srid           = kgd->payload[party->index]->srid;
  kgd->u              = kgd->payload[party->index]->u;
  kgd->V              = kgd->payload[party->index]->V;
  kgd->echo_broadcast = kgd->payload[party->index]->echo_broadcast;

  kgd->run_time = 0;
}

void cmp_key_generation_clean(cmp_party_t *party)
{
  cmp_key_generation_data_t *kgd = party->key_generation_data;

  scalar_free(kgd->tau);
  scalar_free(kgd->secret_x);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  { 
    zkp_schnorr_free(kgd->payload[j]->psi_sch);
    group_elem_free(kgd->payload[j]->public_X);
    group_elem_free(kgd->payload[j]->commited_A);
    free(kgd->payload[j]);
  }
  free(kgd->payload);
  free(kgd);
}

void cmp_key_generation_round_1_commit(hash_chunk commit_digest, const hash_chunk sid_hash, uint64_t party_id, const ec_group_t ec, const cmp_key_generation_payload_t *kg_payload)
{
  uint8_t *temp_bytes = malloc(GROUP_ELEMENT_BYTES);

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, sid_hash, sizeof(hash_chunk));
  SHA512_Update(&sha_ctx, &party_id, sizeof(uint64_t));
  SHA512_Update(&sha_ctx, kg_payload->srid, sizeof(hash_chunk));
  
  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, kg_payload->public_X, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, kg_payload->commited_A, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  SHA512_Update(&sha_ctx, kg_payload->u, sizeof(hash_chunk));
  SHA512_Final(commit_digest, &sha_ctx);
  
  free(temp_bytes);
}

void  cmp_key_generation_round_1_exec (cmp_party_t *party)
{
  printf("### KeyGen Phase, Round 1, Party %lu.\n", party->index);

  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_key_generation_data_t *kgd = party->key_generation_data;

  scalar_sample_in_range(kgd->secret_x, party->ec_order, 0);
  group_operation(kgd->public_X, NULL, party->ec_gen, kgd->secret_x, party->ec);

  kgd->psi_sch->public.G = party->ec;
  kgd->psi_sch->public.g = party->ec_gen;
  zkp_schnorr_commit(kgd->psi_sch, kgd->tau);
  group_elem_copy(kgd->commited_A, kgd->psi_sch->proof.A);

  cmp_sample_bytes(kgd->srid, sizeof(hash_chunk));
  cmp_sample_bytes(kgd->u, sizeof(hash_chunk));

  cmp_key_generation_round_1_commit(kgd->V, party->sid, party->id, party->ec, kgd->payload[party->index]);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;

  // Send payload to parties

  uint64_t send_bytes_len = sizeof(hash_chunk);
  uint8_t *send_bytes = malloc(send_bytes_len);
  uint8_t *curr_send = send_bytes;

  cmp_void_to_bytes(&curr_send, kgd->V, sizeof(hash_chunk), 1);
  
  assert(curr_send == send_bytes + send_bytes_len);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_send_bytes(party->index, j, 11, send_bytes, send_bytes_len);
  }
  free(send_bytes);

  // Print

  printf("Broadcast (V_i).\t>>>\t%lu B, %lu ms\n", send_bytes_len, time_diff);
  printf("V_%lu = ", party->index); printHexBytes("0x", kgd->V, sizeof(hash_chunk), "\n", 0);

  if (!PRINT_SECRETS) return;
  printf("x_%lu = ", party->index); printBIGNUM("", party->secret_x, "\n");
}

void  cmp_key_generation_round_2_exec (cmp_party_t *party)
{
  printf("### KeyGen Phase, Round 2. Party %lu.\n", party->index);

  cmp_key_generation_data_t *kgd = party->key_generation_data;

  // Receive payloads from parties

  uint64_t recv_bytes_len = sizeof(hash_chunk);
  uint8_t *recv_bytes = malloc(recv_bytes_len);
  uint8_t *curr_recv;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_receive_bytes(j, party->index, 11, recv_bytes, recv_bytes_len);
    curr_recv = recv_bytes;

    cmp_void_from_bytes(kgd->payload[j]->V, &curr_recv, sizeof(hash_chunk), 1);

    assert(curr_recv == recv_bytes + recv_bytes_len);

    printf("### Received from Party %lu\t<<<\t%lu B\n", j, recv_bytes_len);
    printf("V_%lu = ", j); printHexBytes("0x", kgd->payload[j]->V, sizeof(hash_chunk), "\n", 0);
  }
  free(recv_bytes);

  // Execute

  clock_t time_start = clock();
  uint64_t time_diff;

  // Echo broadcast - Send hash of all V_i commitments

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t i = 0; i < party->num_parties; ++i) SHA512_Update(&sha_ctx, kgd->payload[i]->V, sizeof(hash_chunk));
  SHA512_Final(kgd->echo_broadcast, &sha_ctx);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;

  // Send payload to parties

  uint64_t send_bytes_len = 3*sizeof(hash_chunk) + 2*GROUP_ELEMENT_BYTES;
  uint8_t *send_bytes = malloc(send_bytes_len);
  uint8_t *curr_send = send_bytes;

  cmp_void_to_bytes(&curr_send, kgd->u, sizeof(hash_chunk), 1);
  cmp_void_to_bytes(&curr_send, kgd->srid, sizeof(hash_chunk), 1);
  cmp_void_to_bytes(&curr_send, kgd->echo_broadcast, sizeof(hash_chunk), 1);
  group_elem_to_bytes(&curr_send, GROUP_ELEMENT_BYTES, kgd->public_X, party->ec, 1);
  group_elem_to_bytes(&curr_send, GROUP_ELEMENT_BYTES, kgd->commited_A, party->ec, 1);
  
  assert(curr_send == send_bytes + send_bytes_len);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_send_bytes(party->index, j, 12, send_bytes, send_bytes_len);
  }
  free(send_bytes);

  // Print 

  printf("### Publish (srid_i, X_i, A_i, u_i, echo_broadcast_i).\t>>>\t%lu B, %lu ms\n", send_bytes_len, time_diff);
  printf("X_%lu = ", party->index); printECPOINT("", kgd->public_X, party->ec, "\n", 1);
  printf("A_%lu = ", party->index); printECPOINT("", kgd->commited_A, party->ec, "\n", 1);
  printf("srid_%lu = ", party->index); printHexBytes("0x", kgd->srid, sizeof(hash_chunk), "\n", 0);
  printf("u_%lu = ", party->index); printHexBytes("0x", kgd->u, sizeof(hash_chunk), "\n", 0);
  printf("echo_broadcast_%lu = ", party->index); printHexBytes("0x", kgd->echo_broadcast, sizeof(hash_chunk), "\n", 0);
}

void  cmp_key_generation_round_3_exec (cmp_party_t *party)
{
  printf("### KeyGen Phase, Round 3, Party %lu.\n", party->index);

  cmp_key_generation_data_t *kgd = party->key_generation_data;

  // Receive payload from parties

  uint64_t recv_bytes_len = 3*sizeof(hash_chunk) + 2*GROUP_ELEMENT_BYTES;
  uint8_t *recv_bytes = malloc(recv_bytes_len);
  uint8_t *curr_recv;
  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_receive_bytes(j, party->index, 12, recv_bytes, recv_bytes_len);
    curr_recv = recv_bytes;

    cmp_void_from_bytes(kgd->payload[j]->u, &curr_recv, sizeof(hash_chunk), 1);
    cmp_void_from_bytes(kgd->payload[j]->srid, &curr_recv, sizeof(hash_chunk), 1);
    cmp_void_from_bytes(kgd->payload[j]->echo_broadcast, &curr_recv, sizeof(hash_chunk), 1);
    group_elem_from_bytes(kgd->payload[j]->public_X, &curr_recv, GROUP_ELEMENT_BYTES, party->ec, 1);
    group_elem_from_bytes(kgd->payload[j]->commited_A, &curr_recv, GROUP_ELEMENT_BYTES, party->ec, 1);
    
    assert(curr_recv == recv_bytes + recv_bytes_len);

    printf("### Received from Party %lu\t<<<\t%lu B\n", j, recv_bytes_len);
    printf("X_%lu = ", j); printECPOINT("", kgd->payload[j]->public_X, party->ec, "\n", 1);
    printf("A_%lu = ", j); printECPOINT("", kgd->payload[j]->commited_A, party->ec, "\n", 1);
    printf("srid_%lu = ", j); printHexBytes("0x", kgd->payload[j]->srid, sizeof(hash_chunk), "\n", 0);
    printf("u_%lu = ", j); printHexBytes("0x", kgd->payload[j]->u, sizeof(hash_chunk), "\n", 0);
    printf("echo_broadcast_%lu = ", j); printHexBytes("0x", kgd->payload[j]->echo_broadcast, sizeof(hash_chunk), "\n", 0);
  }
  free(recv_bytes);

  // Execute round

  clock_t time_start = clock();
  uint64_t time_diff;

  int *verified_decomm = calloc(party->num_parties, sizeof(int));
  int *verified_echo = calloc(party->num_parties, sizeof(int));

  hash_chunk ver_data;
  memcpy(party->srid, kgd->srid, sizeof(hash_chunk));
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    // Verify commited V_i
    cmp_key_generation_round_1_commit(ver_data, party->sid, party->parties_ids[j], party->ec, kgd->payload[j]);
    verified_decomm[j] = memcmp(ver_data, kgd->payload[j]->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment -- ToDo: expand to identification of malicious party
    verified_echo[j] = memcmp(kgd->echo_broadcast, kgd->payload[j]->echo_broadcast, sizeof(hash_chunk)) == 0;

    // Set srid as xor of all party's srid_i
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) party->srid[pos] ^= kgd->payload[j]->srid[pos];
  }

  // Verification log

  for (uint64_t j = 0; j < party->num_parties; ++j){
    if (j == party->index) continue;
    if (verified_decomm[j] != 1) printf("%sParty %lu: decommitment of V_i from Party %lu\n",ERR_STR, party->index, j);
    if (verified_echo[j] != 1)   printf("%sParty %lu: received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->index, j);
  }
  free(verified_decomm);
  free(verified_echo);

  // Aux Info (ssid, i, srid)
  zkp_aux_info_t *aux = zkp_aux_info_new(2*sizeof(hash_chunk) + sizeof(uint64_t), NULL);
  uint64_t aux_pos = 0;
  zkp_aux_info_update_move(aux, &aux_pos, party->sid_hash, sizeof(hash_chunk));
  zkp_aux_info_update_move(aux, &aux_pos, &party->id, sizeof(uint64_t));
  zkp_aux_info_update_move(aux, &aux_pos, party->srid, sizeof(hash_chunk));
  assert(aux->info_len == aux_pos);

  // Set Schnorr ZKP public claim and secret, then prove
  kgd->psi_sch->public.X = kgd->public_X;
  kgd->psi_sch->secret.x = kgd->secret_x;
  zkp_schnorr_prove(kgd->psi_sch, aux, kgd->tau);
  zkp_aux_info_free(aux);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;
  
  // Send payload to parties

  uint64_t psi_sch_byte_len;
  zkp_schnorr_proof_to_bytes(NULL, &psi_sch_byte_len, NULL, 0);
  uint64_t send_bytes_len = psi_sch_byte_len;
  uint8_t *send_bytes = malloc(send_bytes_len);
  uint8_t *curr_send = send_bytes;

  zkp_schnorr_proof_to_bytes(&curr_send, &psi_sch_byte_len, kgd->psi_sch, 1);
  
  assert(curr_send == send_bytes + send_bytes_len);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_send_bytes(party->index, j, 13, send_bytes, send_bytes_len);
  }
  free(send_bytes);
  
  // Print

  printf("### Publish (psi_sch).\t>>>\t%lu B, %lu ms\n", send_bytes_len, time_diff);
  printf("# psi_i = ...\n");
  printHexBytes("combined_srid = 0x", party->srid, sizeof(hash_chunk), "\n", 0);
}

void cmp_key_generation_final_exec(cmp_party_t *party)
{
  printf("### KeyGen Finalization Round, Party %lu.\n", party->index);

  cmp_key_generation_data_t *kgd = party->key_generation_data;

  // Receive payload from parties

  uint64_t psi_sch_byte_len;
  zkp_schnorr_proof_from_bytes(NULL, NULL, &psi_sch_byte_len, 0);
  uint64_t recv_bytes_len = psi_sch_byte_len;
  uint8_t *recv_bytes = malloc(recv_bytes_len);
  uint8_t *curr_recv;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_receive_bytes(j, party->index, 13, recv_bytes, recv_bytes_len);
    curr_recv = recv_bytes;
    
    kgd->payload[j]->psi_sch->public.G = party->ec;
    kgd->payload[j]->psi_sch->public.g = party->ec_gen;
    kgd->payload[j]->psi_sch->public.X = kgd->payload[j]->public_X;
    zkp_schnorr_proof_from_bytes(kgd->payload[j]->psi_sch, &curr_recv, &psi_sch_byte_len, 1);

    assert(curr_recv == recv_bytes + recv_bytes_len);

    printf("### Received from Party %lu\t<<<\t%lu B\n", j, recv_bytes_len);
    printf("# psi_sch_%lu = ...\n", j);
  }
  free(recv_bytes);

  // Execute round

  clock_t time_start = clock();
  uint64_t time_diff;

  int *verified_A   = calloc(party->num_parties, sizeof(int));
  int *verified_psi = calloc(party->num_parties, sizeof(int));

  // Verify all Schnorr ZKP received from parties  

  // Aux Info (ssid, i, srid)
  zkp_aux_info_t *aux = zkp_aux_info_new(2*sizeof(hash_chunk) + sizeof(uint64_t), NULL);
  uint64_t aux_pos = 0;
  zkp_aux_info_update_move(aux, &aux_pos, party->sid_hash, sizeof(hash_chunk));
  zkp_aux_info_update_move(aux, &aux_pos, &party->id, sizeof(uint64_t));      // Changed for each party later
  zkp_aux_info_update_move(aux, &aux_pos, party->srid, sizeof(hash_chunk));
  assert(aux->info_len == aux_pos);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    
    verified_A[j] = group_elem_equal(kgd->payload[j]->psi_sch->proof.A, kgd->payload[j]->commited_A, party->ec);

    zkp_aux_info_update(aux, sizeof(hash_chunk), &party->parties_ids[j], sizeof(uint64_t));              // Update i to commiting player
    verified_psi[j] = zkp_schnorr_verify(kgd->payload[j]->psi_sch, aux);
  }
  zkp_aux_info_free(aux);

  // Verification log

  for (uint64_t j = 0; j < party->num_parties; ++j){
    if (j == party->index) continue;
    if (verified_A[j] != 1) printf("%sParty %lu: schnorr zkp commited A (psi_sch.proof.A) different from previous round from Party %lu\n",ERR_STR, party->index, j);
    if (verified_psi[j] != 1) printf("%sParty %lu: schnorr zkp (psi_sch) failed verification from Party %lu\n",ERR_STR, party->index, j);
  }
  free(verified_A);
  free(verified_psi);
  
  // Set party's values, and update sid_hash to include srid and public_X
  scalar_copy(party->secret_x, kgd->secret_x);
  //scalar_make_plus_minus(party->secret_x, party->ec_order);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    group_elem_copy(party->public_X[j], kgd->payload[j]->public_X);
  }

  // Update sid from updated relevant values
  cmp_set_sid_hash(party, 1);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  kgd->run_time += time_diff;

  // Print

  printf("### Final. Store (srid, all X, secret x_i).\t>>>\t%lu B, %lu ms\n", 
    sizeof(hash_chunk) + GROUP_ORDER_BYTES + party->num_parties * GROUP_ELEMENT_BYTES, time_diff);
}

/******************************************** 
 * 
 *   Key Refresh and Auxiliary Information 
 * 
 ********************************************/

void cmp_refresh_aux_info_init(cmp_party_t *party)
{
  cmp_refresh_data_t *reda = malloc(sizeof(cmp_refresh_data_t));
  party->refresh_data = reda;

  // Initialize payloads from other parties (and sent by self at my index)

  reda->payload = calloc(party->num_parties, sizeof(cmp_refresh_payload_t*));
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    reda->payload[j]                      = malloc(sizeof(cmp_refresh_payload_t));
    reda->payload[j]->paillier_pub        = paillier_encryption_public_new();
    reda->payload[j]->rped_pub            = ring_pedersen_public_new();
    reda->payload[j]->psi_mod             = zkp_paillier_blum_new();
    reda->payload[j]->psi_rped            = zkp_ring_pedersen_param_new();
    reda->payload[j]->psi_sch_k           = calloc(party->num_parties, sizeof(zkp_schnorr_t*)); 
    reda->payload[j]->commited_A_k        = calloc(party->num_parties, sizeof(gr_elem_t));
    reda->payload[j]->encrypted_reshare_k = calloc(party->num_parties, sizeof(scalar_t));
    reda->payload[j]->reshare_public_X_k  = calloc(party->num_parties, sizeof(gr_elem_t));

    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      reda->payload[j]->encrypted_reshare_k[k] = scalar_new();
      reda->payload[j]->reshare_public_X_k[k]  = group_elem_new(party->ec);
      reda->payload[j]->commited_A_k[k]        = group_elem_new(party->ec);
      reda->payload[j]->psi_sch_k[k]           = zkp_schnorr_new();
    }
  }

  // Init self vprivate values

  reda->paillier_priv      = paillier_encryption_private_new();
  reda->rped_priv          = ring_pedersen_private_new();
  reda->reshare_secret_x_j = calloc(party->num_parties, sizeof(scalar_t));
  reda->tau_j              = calloc(party->num_parties, sizeof(scalar_t));
  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    reda->reshare_secret_x_j[j]  = scalar_new();
    reda->tau_j[j]               = scalar_new();
  }
  
  // Pointer to data stored at payload, but generated by self
  reda->encrypted_reshare_j = reda->payload[party->index]->encrypted_reshare_k;
  reda->reshare_public_X_j  = reda->payload[party->index]->reshare_public_X_k;
  reda->commited_A_j        = reda->payload[party->index]->commited_A_k;
  reda->paillier_pub        = reda->payload[party->index]->paillier_pub;
  reda->rped_pub            = reda->payload[party->index]->rped_pub;
  reda->psi_sch_j           = reda->payload[party->index]->psi_sch_k;
  reda->psi_mod             = reda->payload[party->index]->psi_mod;
  reda->psi_rped            = reda->payload[party->index]->psi_rped;
  reda->rho                 = reda->payload[party->index]->rho;
  reda->u                   = reda->payload[party->index]->u;
  reda->V                   = reda->payload[party->index]->V;
  reda->echo_broadcast      = reda->payload[party->index]->echo_broadcast;

  reda->prime_time = 0;
  reda->run_time = 0;
}

void cmp_refresh_aux_info_clean(cmp_party_t *party)
{
  cmp_refresh_data_t *reda = party->refresh_data;

  paillier_encryption_free_keys(reda->paillier_priv, NULL);
  ring_pedersen_free_param(reda->rped_priv, NULL);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    scalar_free(reda->tau_j[j]);
    scalar_free(reda->reshare_secret_x_j[j]);
  }
  free(reda->reshare_secret_x_j);
  free(reda->tau_j);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      scalar_free(reda->payload[j]->encrypted_reshare_k[k]);
      group_elem_free(reda->payload[j]->reshare_public_X_k[k]);
      group_elem_free(reda->payload[j]->commited_A_k[k]);
      zkp_schnorr_free(reda->payload[j]->psi_sch_k[k]);
    }

    paillier_encryption_free_keys(NULL, reda->payload[j]->paillier_pub);
    ring_pedersen_free_param(NULL, reda->payload[j]->rped_pub);
    zkp_paillier_blum_free(reda->payload[j]->psi_mod);
    zkp_ring_pedersen_param_free(reda->payload[j]->psi_rped);

    free(reda->payload[j]->psi_sch_k);
    free(reda->payload[j]->commited_A_k);
    free(reda->payload[j]->encrypted_reshare_k);
    free(reda->payload[j]->reshare_public_X_k);
    free(reda->payload[j]);
  }
  free(reda->payload);
  free(reda);
}

void cmp_refresh_round_1_commit(hash_chunk commit_digest, const hash_chunk sid_hash, uint64_t party_id, uint64_t num_parties, const ec_group_t ec, const cmp_refresh_payload_t *re_payload)
{
  uint8_t *temp_bytes = malloc(PAILLIER_MODULUS_BYTES);     // Enough also for GROUP_ELEMENT_BYTES

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, sid_hash, sizeof(hash_chunk));
  SHA512_Update(&sha_ctx, &party_id, sizeof(uint64_t));

  for (uint64_t k = 0; k < num_parties; ++k)
  {
    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, re_payload->reshare_public_X_k[k], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, re_payload->commited_A_k[k], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  }

  scalar_to_bytes(&temp_bytes, PAILLIER_MODULUS_BYTES, re_payload->paillier_pub->N, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  scalar_to_bytes(&temp_bytes, PAILLIER_MODULUS_BYTES, re_payload->rped_pub->N, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  scalar_to_bytes(&temp_bytes, PAILLIER_MODULUS_BYTES, re_payload->rped_pub->s, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  scalar_to_bytes(&temp_bytes, PAILLIER_MODULUS_BYTES, re_payload->rped_pub->t, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  SHA512_Update(&sha_ctx, re_payload->rho, sizeof(hash_chunk));
  SHA512_Update(&sha_ctx, re_payload->u, sizeof(hash_chunk));
  SHA512_Final(commit_digest, &sha_ctx);
  
  free(temp_bytes);
}

void cmp_refresh_aux_info_round_1_exec (cmp_party_t *party)
{
  printf("### Refresh Phase, Round 1, Party %lu.\n", party->index);

  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_refresh_data_t *reda = party->refresh_data;

  paillier_encryption_generate_private(reda->paillier_priv, 4*PAILLIER_MODULUS_BYTES);
  ring_pedersen_generate_private(reda->rped_priv, 4*RING_PED_MODULUS_BYTES);
  paillier_encryption_copy_keys(NULL, reda->paillier_pub, reda->paillier_priv, NULL);
  ring_pedersen_copy_param(NULL, reda->rped_pub, reda->rped_priv, NULL);
  
  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->prime_time = time_diff;

  time_start = clock();
  
  // Sample other parties' reshares, set negative of sum for self
  scalar_set_ul(reda->reshare_secret_x_j[party->index], 0);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    // Initialize relevant zkp
    reda->psi_sch_j[j]->public.G = party->ec;
    reda->psi_sch_j[j]->public.g = party->ec_gen;
    zkp_schnorr_commit(reda->psi_sch_j[j], reda->tau_j[j]);
    group_elem_copy(reda->commited_A_j[j], reda->psi_sch_j[j]->proof.A);

    // Dont choose your own values
    if (j == party->index) continue; 

    scalar_sample_in_range(reda->reshare_secret_x_j[j], party->ec_order, 0);
    group_operation(reda->reshare_public_X_j[j], NULL, party->ec_gen, reda->reshare_secret_x_j[j], party->ec);
    scalar_sub(reda->reshare_secret_x_j[party->index], reda->reshare_secret_x_j[party->index], reda->reshare_secret_x_j[j], party->ec_order);
  }
  group_operation(reda->reshare_public_X_j[party->index], NULL, party->ec_gen, reda->reshare_secret_x_j[party->index], party->ec);
  cmp_sample_bytes(reda->rho, sizeof(hash_chunk));
  cmp_sample_bytes(reda->u, sizeof(hash_chunk));

  cmp_refresh_round_1_commit(reda->V, party->sid, party->id, party->num_parties, party->ec, reda->payload[party->index]);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;

  // Send payload 
  
  uint64_t send_bytes_len = sizeof(hash_chunk);
  uint8_t *send_bytes = malloc(send_bytes_len);
  uint8_t *curr_send = send_bytes;

  cmp_void_to_bytes(&curr_send, reda->V, sizeof(hash_chunk), 1);
  
  assert(curr_send == send_bytes + send_bytes_len);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_send_bytes(party->index, j, 21, send_bytes, send_bytes_len);
  }
  free(send_bytes);

  // Print

  printf("### Broadcast (V_i).\t>>>\t%lu B, %lu ms (gen N_i) + %lu ms (rest)\n", send_bytes_len, reda->prime_time, time_diff);;
  printf("V_%lu = ", party->index); printHexBytes("0x", reda->V, sizeof(hash_chunk), "\n", 0);

  if (!PRINT_SECRETS) return;
  printf("paillier_p_%lu = ", party->index); printBIGNUM("", reda->paillier_priv->p, "\n");
  printf("paillier_q_%lu = ", party->index); printBIGNUM("", reda->paillier_priv->q, "\n");
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    printf("x_%lue%lu = ", party->index, j); printBIGNUM("", reda->reshare_secret_x_j[j], "\n");
  }
}

void  cmp_refresh_aux_info_round_2_exec (cmp_party_t *party)
{
  printf("### Refresh Phase, Round 1, Party %lu.\n", party->index);

  cmp_refresh_data_t *reda = party->refresh_data;

  // Receive payloads from parties

  uint64_t recv_bytes_len = sizeof(hash_chunk);
  uint8_t *recv_bytes = malloc(recv_bytes_len);
  uint8_t *curr_recv;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_receive_bytes(j, party->index, 21, recv_bytes, recv_bytes_len);
    curr_recv = recv_bytes;

    cmp_void_from_bytes(reda->payload[j]->V, &curr_recv, sizeof(hash_chunk), 1);

    assert(curr_recv == recv_bytes + recv_bytes_len);

    printf("### Received from Party %lu\t<<<\t%lu B\n", j, recv_bytes_len);
    printf("V_%lu = ", j); printHexBytes("0x", reda->payload[j]->V, sizeof(hash_chunk), "\n", 0);
  }
  free(recv_bytes);

  // Execute Round

  clock_t time_start = clock();
  uint64_t time_diff;

  // Echo broadcast - Hash of all V_i commitments

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t i = 0; i < party->num_parties; ++i) SHA512_Update(&sha_ctx, reda->payload[i]->V, sizeof(hash_chunk));
  SHA512_Final(reda->echo_broadcast, &sha_ctx);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;

  // Send payload

  uint64_t paillier_bytelen;
  uint64_t rped_bytelen;
  paillier_public_to_bytes(NULL, &paillier_bytelen, NULL, PAILLIER_MODULUS_BYTES, 0);
  ring_pedersen_public_to_bytes(NULL, &rped_bytelen, NULL, RING_PED_MODULUS_BYTES, 0);

  uint64_t send_bytes_len =  3*sizeof(hash_chunk) + paillier_bytelen + rped_bytelen + 2*party->num_parties*GROUP_ELEMENT_BYTES;
  uint8_t *send_bytes = malloc(send_bytes_len);
  uint8_t *curr_send = send_bytes;

  cmp_void_to_bytes(&curr_send, reda->u, sizeof(hash_chunk), 1);
  cmp_void_to_bytes(&curr_send, reda->rho, sizeof(hash_chunk), 1);
  cmp_void_to_bytes(&curr_send, reda->echo_broadcast, sizeof(hash_chunk), 1);

  paillier_public_to_bytes(&curr_send, &paillier_bytelen, reda->paillier_pub, PAILLIER_MODULUS_BYTES, 1);
  ring_pedersen_public_to_bytes(&curr_send, &rped_bytelen, reda->rped_pub, RING_PED_MODULUS_BYTES, 1);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    group_elem_to_bytes(&curr_send, GROUP_ELEMENT_BYTES, reda->reshare_public_X_j[j], party->ec, 1);
    group_elem_to_bytes(&curr_send, GROUP_ELEMENT_BYTES, reda->commited_A_j[j], party->ec, 1);
  }
  
  assert(curr_send == send_bytes + send_bytes_len);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    cmp_comm_send_bytes(party->index, j, 22, send_bytes, send_bytes_len);
  }
  free(send_bytes);

  // Print 

  printf("### Publishe (X_i^{1...n}, A_i^{1...n}, Paillier N_i, Pedersen N_i, s_i, t_i, rho_i, u_i, echo_broadcast).\t>>>\t%lu B, %lu ms\n", send_bytes_len, time_diff);
  printf("echo_broadcast_%lu = ", party->index); printHexBytes("echo_broadcast = 0x", reda->echo_broadcast, sizeof(hash_chunk), "\n", 0);
  printf("rho_%lu = ", party->index); printHexBytes("0x", reda->rho, sizeof(hash_chunk), "\n", 0);
  printf("u_%lu = ", party->index); printHexBytes("0x", reda->u, sizeof(hash_chunk), "\n", 0);
  printf("paillier_N_%lu = ", party->index); printBIGNUM("", reda->paillier_pub->N, "\n");
  printf("rped_N_%lu = ", party->index); printBIGNUM("", reda->rped_pub->N, "\n");
  printf("s_%lu = ", party->index); printBIGNUM("", reda->rped_pub->s, "\n");
  printf("t_%lu = ", party->index); printBIGNUM("", reda->rped_pub->t, "\n");

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    printf("X_%lue%lu = ", party->index, j); printECPOINT("", reda->reshare_public_X_j[j], party->ec, "\n", 1);
    printf("A_%lue%lu = ", party->index, j); printECPOINT("", reda->commited_A_j[j], party->ec, "\n", 1);
  }
}

void  cmp_refresh_aux_info_round_3_exec (cmp_party_t *party)
{
  printf("### Refresh Phase, Round 3, Party %lu.\n", party->index);

  cmp_refresh_data_t *reda = party->refresh_data;

  // Receive payloads from parties

  uint64_t paillier_bytelen;
  uint64_t rped_bytelen;
  paillier_public_to_bytes(NULL, &paillier_bytelen, NULL, PAILLIER_MODULUS_BYTES, 0);
  ring_pedersen_public_to_bytes(NULL, &rped_bytelen, NULL, RING_PED_MODULUS_BYTES, 0);

  uint64_t recv_bytes_len =  3*sizeof(hash_chunk) + paillier_bytelen + rped_bytelen + 2*party->num_parties*GROUP_ELEMENT_BYTES;
  uint8_t *recv_bytes = malloc(recv_bytes_len);
  uint8_t *curr_recv;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_receive_bytes(j, party->index, 22, recv_bytes, recv_bytes_len);
    curr_recv = recv_bytes;

    cmp_void_from_bytes(reda->payload[j]->u, &curr_recv, sizeof(hash_chunk), 1);
    cmp_void_from_bytes(reda->payload[j]->rho, &curr_recv, sizeof(hash_chunk), 1);
    cmp_void_from_bytes(reda->payload[j]->echo_broadcast, &curr_recv, sizeof(hash_chunk), 1);

    paillier_public_from_bytes(reda->payload[j]->paillier_pub, &curr_recv, &paillier_bytelen, PAILLIER_MODULUS_BYTES, 1);
    ring_pedersen_public_from_bytes(reda->payload[j]->rped_pub, &curr_recv, &rped_bytelen, RING_PED_MODULUS_BYTES, 1);
  
    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      group_elem_from_bytes(reda->payload[j]->reshare_public_X_k[k], &curr_recv, GROUP_ELEMENT_BYTES, party->ec, 1);
      group_elem_from_bytes(reda->payload[j]->commited_A_k[k], &curr_recv, GROUP_ELEMENT_BYTES, party->ec, 1);
    }

    assert(curr_recv == recv_bytes + recv_bytes_len);

    printf("### Received from Party %lu\t<<<\t%lu B\n", j, recv_bytes_len);
    printf("echo_broadcast_%lu = ", j); printHexBytes("echo_broadcast = 0x", reda->payload[j]->echo_broadcast, sizeof(hash_chunk), "\n", 0);
    printf("rho_%lu = ", j); printHexBytes("0x", reda->payload[j]->rho, sizeof(hash_chunk), "\n", 0);
    printf("u_%lu = ", j); printHexBytes("0x", reda->payload[j]->u, sizeof(hash_chunk), "\n", 0);
    printf("paillier_N_%lu = ", j); printBIGNUM("", reda->payload[j]->paillier_pub->N, "\n");
    printf("rped_N_%lu = ", j); printBIGNUM("", reda->payload[j]->rped_pub->N, "\n");
    printf("s_%lu = ", j); printBIGNUM("", reda->payload[j]->rped_pub->s, "\n");
    printf("t_%lu = ", j); printBIGNUM("", reda->payload[j]->rped_pub->t, "\n");

    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      printf("X_%lue%lu = ", j, k); printECPOINT("", reda->payload[j]->reshare_public_X_k[k], party->ec, "\n", 1);
      printf("A_%lue%lu = ", j, k); printECPOINT("", reda->payload[j]->commited_A_k[k], party->ec, "\n", 1);
    }
  }
  free(recv_bytes);

  // Execute round

  clock_t time_start = clock();
  uint64_t time_diff;

  gr_elem_t combined_public = group_elem_new(party->ec);

  // Verification

  int *verified_modulus_size = calloc(party->num_parties, sizeof(int));
  int *verified_public_shares = calloc(party->num_parties, sizeof(int));
  int *verified_decomm = calloc(party->num_parties, sizeof(int));
  int *verified_echo = calloc(party->num_parties, sizeof(int));

  hash_chunk ver_data;
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    // Verify modulus size
    verified_modulus_size[j] = scalar_bitlength(reda->payload[j]->paillier_pub->N) >= 8*PAILLIER_MODULUS_BYTES-1;

    // Verify shared public X_j^k is valid from party j
    group_operation(combined_public, NULL, NULL, NULL, party->ec);
    for (uint64_t k = 0; k < party->num_parties; ++k) {
      group_operation(combined_public, combined_public, reda->payload[j]->reshare_public_X_k[k], NULL, party->ec);
    }
    verified_public_shares[j] = group_elem_is_ident(combined_public, party->ec) == 1;

    // Verify commited V_i
    cmp_refresh_round_1_commit(ver_data, party->sid, party->parties_ids[j], party->num_parties, party->ec, reda->payload[j]);
    verified_decomm[j] = memcmp(ver_data, reda->payload[j]->V, sizeof(hash_chunk)) == 0;

    // Verify echo broadcast of round 1 commitment -- ToDo: expand to identification of malicious party
    verified_echo[j] = memcmp(reda->echo_broadcast, reda->payload[j]->echo_broadcast, sizeof(hash_chunk)) == 0;

    if (verified_modulus_size[j] != 1)  printf("%sParty %lu: N_i bitlength from Party %lu\n",ERR_STR, party->index, j);
    if (verified_public_shares[j] != 1) printf("%sParty %lu: invalid X_j_k sharing from Party %lu\n",ERR_STR, party->index, j);
    if (verified_decomm[j] != 1)        printf("%sParty %lu: decommitment of V_i from Party %lu\n",ERR_STR, party->index, j);
    if (verified_echo[j] != 1)          printf("%sParty %lu: received different echo broadcast of round 1 from Party %lu\n",ERR_STR, party->index, j);
  }

  free(verified_modulus_size);
  free(verified_public_shares);
  free(verified_decomm);
  free(verified_echo);
  group_elem_free(combined_public);

  // Computation

  // Set combined rho as xor of all party's rho_i
  memset(reda->combined_rho, 0x00, sizeof(hash_chunk));
  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) reda->combined_rho[pos] ^= reda->payload[i]->rho[pos];
  }

  // AuxInfo for ZKP (ssid, i, combined rho)
  zkp_aux_info_t *aux = zkp_aux_info_new(sizeof(uint64_t) + 2*sizeof(hash_chunk), NULL);
  uint64_t aux_pos = 0;
  zkp_aux_info_update_move(aux, &aux_pos, party->sid_hash, sizeof(hash_chunk));
  zkp_aux_info_update_move(aux, &aux_pos, &party->id, sizeof(uint64_t));
  zkp_aux_info_update_move(aux, &aux_pos, reda->combined_rho, sizeof(hash_chunk));
  assert(aux->info_len == aux_pos);

  // Generate ZKP, set public claim and secret, then prove
  reda->psi_mod->public  = reda->paillier_pub;
  reda->psi_mod->private = reda->paillier_priv;
  zkp_paillier_blum_prove(reda->psi_mod, aux);

  reda->psi_rped->rped_pub = reda->rped_pub;
  reda->psi_rped->secret   = reda->rped_priv;
  zkp_ring_pedersen_param_prove(reda->psi_rped, aux);

  // Encrypt refresh shares and Schnorr prove
  scalar_t temp_paillier_rand = scalar_new();
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    // Encrypt all secret reshares (including own) - TODO add echo broadcast on these
    paillier_encryption_sample(temp_paillier_rand, reda->payload[j]->paillier_pub);
    paillier_encryption_encrypt(reda->encrypted_reshare_j[j], reda->reshare_secret_x_j[j], temp_paillier_rand, reda->payload[j]->paillier_pub);

    reda->psi_sch_j[j]->public.X = reda->reshare_public_X_j[j];
    reda->psi_sch_j[j]->secret.x = reda->reshare_secret_x_j[j];
    zkp_schnorr_prove(reda->psi_sch_j[j], aux, reda->tau_j[j]);
  }
  scalar_free(temp_paillier_rand);
  zkp_aux_info_free(aux);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;
  
  // Send payload

  uint64_t psi_rped_bytelen;
  uint64_t psi_mod_bytelen;
  uint64_t psi_sch_bytelen;
  zkp_ring_pedersen_param_proof_to_bytes(NULL, &psi_rped_bytelen, NULL, 0);
  zkp_paillier_blum_proof_to_bytes(NULL, &psi_mod_bytelen, NULL, 0);
  zkp_schnorr_proof_to_bytes(NULL, &psi_sch_bytelen, NULL, 0);

  uint64_t send_bytes_len =  psi_mod_bytelen + psi_rped_bytelen + party->num_parties * (psi_sch_bytelen + 2*PAILLIER_MODULUS_BYTES);
  uint8_t *send_bytes = malloc(send_bytes_len);
  uint8_t *curr_send = send_bytes;

  zkp_paillier_blum_proof_to_bytes(&curr_send, &psi_mod_bytelen, reda->psi_mod, 1);
  zkp_ring_pedersen_param_proof_to_bytes(&curr_send, &psi_rped_bytelen, reda->psi_rped, 1);
  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    zkp_schnorr_proof_to_bytes(&curr_send, &psi_sch_bytelen, reda->psi_sch_j[j], 1);
    scalar_to_bytes(&curr_send, 2*PAILLIER_MODULUS_BYTES, reda->encrypted_reshare_j[j], 1);
  }
  
  assert(curr_send == send_bytes + send_bytes_len);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    cmp_comm_send_bytes(party->index, j, 23, send_bytes, send_bytes_len);
  }
  free(send_bytes);

  // Print

  printf("### Publishe (psi_mod, psi_rped, psi_sch^j, Enc_j(x_i^j)).\t>>>\t%lu B, %lu ms\n", send_bytes_len, time_diff);
  printHexBytes("combined rho = 0x", reda->combined_rho, sizeof(hash_chunk), "\n", 0);
  printf("# psi_mod_i = ...\n");
  printf("# psi_rped_i = ...\n");
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    printf("# psi_sch_i_%lu = ...\n", j);
    printf("Enc_%lu(x_%lue%lu) = ", j, party->index, j); printBIGNUM("", reda->encrypted_reshare_j[j], "\n");
  }
}

void cmp_refresh_aux_info_final_exec(cmp_party_t *party)
{
  printf("### Refresh Phase, Finalization Round, Party %lu.\n", party->index);

  cmp_refresh_data_t *reda = party->refresh_data;

  // Receive payloads from parties

  uint64_t psi_rped_bytelen;
  uint64_t psi_mod_bytelen;
  uint64_t psi_sch_bytelen;
  zkp_ring_pedersen_param_proof_to_bytes(NULL, &psi_rped_bytelen, NULL, 0);
  zkp_paillier_blum_proof_to_bytes(NULL, &psi_mod_bytelen, NULL, 0);
  zkp_schnorr_proof_to_bytes(NULL, &psi_sch_bytelen, NULL, 0);

  uint64_t recv_bytes_len = psi_mod_bytelen + psi_rped_bytelen + party->num_parties * (psi_sch_bytelen + 2*PAILLIER_MODULUS_BYTES);
  uint8_t *recv_bytes = malloc(recv_bytes_len);
  uint8_t *curr_recv;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_receive_bytes(j, party->index, 23, recv_bytes, recv_bytes_len);
    curr_recv = recv_bytes;
    
    reda->payload[j]->psi_mod->public = reda->payload[j]->paillier_pub;
    zkp_paillier_blum_proof_from_bytes(reda->payload[j]->psi_mod, &curr_recv, &psi_mod_bytelen, 1);

    reda->payload[j]->psi_rped->rped_pub = reda->payload[j]->rped_pub;
    zkp_ring_pedersen_param_proof_from_bytes(reda->payload[j]->psi_rped, &curr_recv, &psi_rped_bytelen, 1);
    
    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      reda->payload[j]->psi_sch_k[k]->public.G = party->ec;
      reda->payload[j]->psi_sch_k[k]->public.g = party->ec_gen;
      reda->payload[j]->psi_sch_k[k]->public.X = reda->payload[j]->reshare_public_X_k[k];
      zkp_schnorr_proof_from_bytes(reda->payload[j]->psi_sch_k[k], &curr_recv, &psi_sch_bytelen, 1);
      scalar_from_bytes(reda->payload[j]->encrypted_reshare_k[k], &curr_recv, 2*PAILLIER_MODULUS_BYTES, 1);
    }

    assert(curr_recv == recv_bytes + recv_bytes_len);

    printf("### Received from Party %lu\t<<<\t%lu B\n", j, recv_bytes_len);
    printf("# psi_mod_%lu = ...\n", j);
    printf("# psi_rped_%lu = ...\n", j);
    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      printf("# psi_sch_%lu = ...\n", k);
      printf("Enc_%lu(x_%lue%lu) = ", k, j, k); printBIGNUM("", reda->payload[j]->encrypted_reshare_k[k], "\n");
    }
  }
  free(recv_bytes);

  // Execute round

  clock_t time_start = clock();
  uint64_t time_diff;

  // Verify all Schnorr ZKP and values received from parties  

  int *verified_reshare   = calloc(party->num_parties, sizeof(int));
  int *verified_psi_mod   = calloc(party->num_parties, sizeof(int));
  int *verified_psi_rped  = calloc(party->num_parties, sizeof(int));
  int *verified_psi_sch_k = calloc(party->num_parties*party->num_parties, sizeof(int));
  int *verified_A_k       = calloc(party->num_parties*party->num_parties, sizeof(int));

  // Aux Info for ZKP (ssid, i, combined rho)
  zkp_aux_info_t *aux = zkp_aux_info_new(sizeof(uint64_t) + 2*sizeof(hash_chunk), NULL);
  uint64_t aux_pos = 0;
  zkp_aux_info_update_move(aux, &aux_pos, party->sid_hash, sizeof(hash_chunk));
  zkp_aux_info_update_move(aux, &aux_pos, &party->id, sizeof(uint64_t));                // Will be changed for each verified party
  zkp_aux_info_update_move(aux, &aux_pos, reda->combined_rho, sizeof(hash_chunk));
  assert(aux->info_len == aux_pos);

  scalar_t received_reshare = scalar_new();
  scalar_t sum_received_reshares = scalar_new();
  gr_elem_t ver_public = group_elem_new(party->ec);
  
  // Sum all secret reshares, self and generated by others for self
  scalar_copy(sum_received_reshares, reda->reshare_secret_x_j[party->index]);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  { 
    if (j == party->index) continue; 

    // Decrypt and verify reshare secret vs public   
    paillier_encryption_decrypt(received_reshare, reda->payload[j]->encrypted_reshare_k[party->index], reda->paillier_priv);
    scalar_add(sum_received_reshares, sum_received_reshares, received_reshare, party->ec_order);
    group_operation(ver_public, NULL, party->ec_gen, received_reshare, party->ec);
    verified_reshare[j] = group_elem_equal(ver_public, reda->payload[j]->reshare_public_X_k[party->index], party->ec) == 1;

    // Verify ZKP
    zkp_aux_info_update(aux, sizeof(hash_chunk), &party->parties_ids[j], sizeof(uint64_t));                  // Update i to commiting player
    verified_psi_mod[j] = zkp_paillier_blum_verify(reda->payload[j]->psi_mod, aux) == 1;
    verified_psi_rped[j] = zkp_ring_pedersen_param_verify(reda->payload[j]->psi_rped, aux) == 1;

    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      verified_A_k[k + party->num_parties*j] = group_elem_equal(reda->payload[j]->psi_sch_k[k]->proof.A, reda->payload[j]->commited_A_k[k], party->ec) == 1;
      verified_psi_sch_k[k + party->num_parties*j] = (zkp_schnorr_verify(reda->payload[j]->psi_sch_k[k], aux) == 1);
    }
  }
  scalar_free(received_reshare);
  zkp_aux_info_free(aux);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    if (verified_reshare[j] != 1)  printf("%sParty %lu: Public reshare inconsistent from Party %lu\n",ERR_STR, party->index, j);
    if (verified_psi_mod[j] != 1)  printf("%sParty %lu: Paillier-Blum ZKP failed verification from Party %lu\n",ERR_STR, party->index, j);
    if (verified_psi_rped[j] != 1) printf("%sParty %lu: Ring-Pedersen ZKP failed verification from Party %lu\n",ERR_STR, party->index, j);
    for (uint64_t k = 0; k < party->num_parties; ++k)
    {
      if (verified_psi_sch_k[k + party->num_parties*j] != 1) printf("%sParty %lu: Schnorr ZKP failed verification from Party %lu for Party %lu\n",ERR_STR, party->index, j, k);

      if (verified_A_k[k + party->num_parties*j] != 1) printf("%sParty %lu: schnorr zkp commited A (psi_sch.proof.A) different from previous round from Party %lu for Party %lu\n",ERR_STR, party->index, j, k);
    }
  }

  free(verified_reshare);
  free(verified_psi_mod);
  free(verified_psi_rped);
  free(verified_psi_sch_k);
  free(verified_A_k);
  group_elem_free(ver_public);

  // Refresh Party's keys
  paillier_encryption_copy_keys(party->paillier_priv, party->paillier_pub[party->index], reda->paillier_priv, NULL);
  ring_pedersen_copy_param(NULL, party->rped_pub[party->index], reda->rped_priv, NULL);

    // Update key shares
  scalar_add(party->secret_x, party->secret_x, sum_received_reshares, party->ec_order);
  scalar_free(sum_received_reshares);

  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    for (uint64_t k = 0; k < party->num_parties; ++k) group_operation(party->public_X[k], party->public_X[k], reda->payload[i]->reshare_public_X_k[k], NULL, party->ec);

    if (i == party->index) continue; // Self copied before loop
    paillier_encryption_copy_keys(NULL, party->paillier_pub[i], NULL, reda->payload[i]->paillier_pub);
    ring_pedersen_copy_param(NULL, party->rped_pub[i], NULL, reda->payload[i]->rped_pub);
  }

  // UDIBUG: Sanity Check of self public key vs private
  gr_elem_t check_my_public = group_elem_new(party->ec);
  group_operation(check_my_public, NULL, party->ec_gen, party->secret_x, party->ec);
  assert( group_elem_equal(check_my_public, party->public_X[party->index], party->ec) == 1);
  group_elem_free(check_my_public);

  // Update sid from current party values
  cmp_set_sid_hash(party, 2);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  reda->run_time += time_diff;
  
  // Print

  printf("### Stores fresh (secret x_i, all public X, paillier_N_i, rped_N_i, s_i, t_i).\t>>>\t%lu B, %lu ms\n", GROUP_ORDER_BYTES + party->num_parties*(GROUP_ELEMENT_BYTES + PAILLIER_MODULUS_BYTES + 3*RING_PED_MODULUS_BYTES), time_diff);

  for (uint64_t i = 0; i < party->num_parties; ++i) 
  {
    printf("X_%lu = ", i); printECPOINT("", party->public_X[i], party->ec, "\n", 1);
    printf("paillier_N_%lu = ", i); printBIGNUM("", party->paillier_pub[i]->N, "\n");
    printf("rped_N_%lu = ", i); printBIGNUM("", party->rped_pub[i]->N, "\n");
    printf("s_%lu = ", i); printBIGNUM("", party->rped_pub[i]->s, "\n");
    printf("t_%lu = ", i); printBIGNUM("", party->rped_pub[i]->t, "\n");
  }

  if (!PRINT_SECRETS) return;
  printf("fresh_x_%lu = ", party->index); printBIGNUM("", party->secret_x, "\n");
}

/******************************************** 
 * 
 *   Pre-Signing
 * 
 ********************************************/


void cmp_presign_init(cmp_party_t *party)
{
  cmp_presign_data_t *preda = malloc(sizeof(*preda));
  party->presign_data = preda;

  // Initialize payloads from other parties (and sent by self at my index)

  preda->payload = calloc(party->num_parties, sizeof(cmp_presign_payload_t*));
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    preda->payload[j]        = malloc(sizeof(cmp_presign_payload_t));

    preda->payload[j]->G     = scalar_new();
    preda->payload[j]->K     = scalar_new();
    preda->payload[j]->D     = scalar_new();
    preda->payload[j]->F     = scalar_new();
    preda->payload[j]->Dhat  = scalar_new();
    preda->payload[j]->Fhat  = scalar_new();
    preda->payload[j]->delta = scalar_new();
    preda->payload[j]->Delta = group_elem_new(party->ec);
    preda->payload[j]->Gamma = group_elem_new(party->ec);
    
    preda->payload[j]->psi_enc  = zkp_encryption_in_range_new();
    preda->payload[j]->psi_affp = zkp_operation_paillier_commitment_range_new();
    preda->payload[j]->psi_affg = zkp_operation_group_commitment_range_new();
    preda->payload[j]->psi_logG = zkp_group_vs_paillier_range_new();
    preda->payload[j]->psi_logK = zkp_group_vs_paillier_range_new();
  }

  // Init self private values

  preda->k     = scalar_new();
  preda->rho   = scalar_new();
  preda->nu    = scalar_new();
  preda->gamma = scalar_new();
  preda->chi   = scalar_new();

  //preda->alpha_j    = calloc(party->num_parties, sizeof(scalar_t));
  preda->beta_j     = calloc(party->num_parties, sizeof(scalar_t));
  //preda->alphahat_j = calloc(party->num_parties, sizeof(scalar_t));
  preda->betahat_j  = calloc(party->num_parties, sizeof(scalar_t));
  preda->D_j        = calloc(party->num_parties, sizeof(scalar_t));
  preda->F_j        = calloc(party->num_parties, sizeof(scalar_t));
  preda->Dhat_j     = calloc(party->num_parties, sizeof(scalar_t));
  preda->Fhat_j     = calloc(party->num_parties, sizeof(scalar_t));

  preda->psi_enc_j  = calloc(party->num_parties, sizeof(zkp_encryption_in_range_t));
  preda->psi_affp_j = calloc(party->num_parties, sizeof(zkp_operation_paillier_commitment_range_t));
  preda->psi_affg_j = calloc(party->num_parties, sizeof(zkp_operation_group_commitment_range_t));
  preda->psi_logG_j = calloc(party->num_parties, sizeof(zkp_group_vs_paillier_range_t));
  preda->psi_logK_j = calloc(party->num_parties, sizeof(zkp_group_vs_paillier_range_t));

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    //preda->alpha_j[j]    = scalar_new();
    preda->beta_j[j]     = scalar_new();
    //preda->alphahat_j[j] = scalar_new();
    preda->betahat_j[j]  = scalar_new();
    preda->D_j[j]        = scalar_new();
    preda->F_j[j]        = scalar_new();
    preda->Dhat_j[j]     = scalar_new();
    preda->Fhat_j[j]     = scalar_new();
    
    preda->psi_enc_j[j]  = zkp_encryption_in_range_new();
    preda->psi_affp_j[j] = zkp_operation_paillier_commitment_range_new();
    preda->psi_affg_j[j] = zkp_operation_group_commitment_range_new();
    preda->psi_logG_j[j] = zkp_group_vs_paillier_range_new();
    preda->psi_logK_j[j] = zkp_group_vs_paillier_range_new();
  }

  preda->combined_Gamma = group_elem_new(party->ec);
  
  // Pointer to data stored at payload, but generated by self
  preda->G              = preda->payload[party->index]->G;
  preda->K              = preda->payload[party->index]->K;
  preda->delta          = preda->payload[party->index]->delta;
  preda->Delta          = preda->payload[party->index]->Delta;
  preda->Gamma          = preda->payload[party->index]->Gamma;
  preda->echo_broadcast = preda->payload[party->index]->echo_broadcast;

  preda->run_time = 0;
}

void cmp_presign_clean(cmp_party_t *party)
{
  cmp_presign_data_t *preda = party->presign_data;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    scalar_free(preda->payload[j]->G);
    scalar_free(preda->payload[j]->K);
    scalar_free(preda->payload[j]->D);
    scalar_free(preda->payload[j]->F);
    scalar_free(preda->payload[j]->Dhat);
    scalar_free(preda->payload[j]->Fhat);
    scalar_free(preda->payload[j]->delta);
    group_elem_free(preda->payload[j]->Delta);
    group_elem_free(preda->payload[j]->Gamma);

    zkp_encryption_in_range_free(preda->payload[j]->psi_enc );
    zkp_operation_paillier_commitment_range_free(preda->payload[j]->psi_affp);
    zkp_operation_group_commitment_range_free(preda->payload[j]->psi_affg);
    zkp_group_vs_paillier_range_free(preda->payload[j]->psi_logG);
    zkp_group_vs_paillier_range_free(preda->payload[j]->psi_logK);

    free(preda->payload[j]);
  }
  free(preda->payload);

  scalar_free(preda->k);
  scalar_free(preda->rho);
  scalar_free(preda->nu);
  scalar_free(preda->gamma);
  scalar_free(preda->chi);

  group_elem_free(preda->combined_Gamma);

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    //scalar_free(preda->alpha_j[j]);
    scalar_free(preda->beta_j[j] );
    //scalar_free(preda->alphahat_j[j]);
    scalar_free(preda->betahat_j[j]);
    scalar_free(preda->D_j[j]);
    scalar_free(preda->F_j[j]);
    scalar_free(preda->Dhat_j[j]);
    scalar_free(preda->Fhat_j[j]);

    zkp_encryption_in_range_free(preda->psi_enc_j [j]);
    zkp_operation_paillier_commitment_range_free(preda->psi_affp_j[j]);
    zkp_operation_group_commitment_range_free(preda->psi_affg_j[j]);
    zkp_group_vs_paillier_range_free(preda->psi_logG_j[j]);
    zkp_group_vs_paillier_range_free(preda->psi_logK_j[j]);
  }

  //free(preda->alphahat_j);
  free(preda->betahat_j );
  //free(preda->alpha_j);
  free(preda->beta_j);
  free(preda->D_j);
  free(preda->F_j);
  free(preda->Dhat_j);
  free(preda->Fhat_j);

  free(preda->psi_enc_j);
  free(preda->psi_affp_j);
  free(preda->psi_affg_j);
  free(preda->psi_logG_j);
  free(preda->psi_logK_j);
  free(preda);
}

void cmp_presign_round_1_exec (cmp_party_t *party)
{
   printf("### Presign Phase, Round 1, Party %lu.\n", party->index);

  clock_t time_start = clock();
  uint64_t time_diff;

  cmp_presign_data_t *preda = party->presign_data;

  paillier_encryption_sample(preda->rho, party->paillier_pub[party->index]);
  scalar_sample_in_range(preda->k, party->ec_order, 0);
  paillier_encryption_encrypt(preda->K, preda->k, preda->rho, party->paillier_pub[party->index]);

  paillier_encryption_sample(preda->nu, party->paillier_pub[party->index]);
  scalar_sample_in_range(preda->gamma, party->ec_order, 0);
  paillier_encryption_encrypt(preda->G, preda->gamma, preda->nu, party->paillier_pub[party->index]);

  // Aux Info for ZKP (ssid, i)
  zkp_aux_info_t *aux = zkp_aux_info_new(sizeof(uint64_t) + sizeof(hash_chunk), NULL);
  uint64_t aux_pos = 0;
  zkp_aux_info_update_move(aux, &aux_pos, party->sid_hash, sizeof(hash_chunk));
  zkp_aux_info_update_move(aux, &aux_pos, &party->id, sizeof(uint64_t));
  assert(aux->info_len == aux_pos);

  for (uint64_t j = 0; j < party->num_parties; ++j) 
  {
    if (j == party->index) continue;

    preda->psi_enc_j[j]->public.paillier_pub = party->paillier_pub[party->index];
    preda->psi_enc_j[j]->public.rped_pub = party->rped_pub[j];
    preda->psi_enc_j[j]->public.G = party->ec;
    preda->psi_enc_j[j]->public.K = preda->K;
    preda->psi_enc_j[j]->public.k_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    preda->psi_enc_j[j]->secret.k = preda->k;
    preda->psi_enc_j[j]->secret.rho = preda->rho;
    zkp_encryption_in_range_prove(preda->psi_enc_j[j], aux);
  }
  //zkp_aux_info_free(aux);
  
  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  preda->run_time += time_diff;

  // Send payload

  uint64_t psi_enc_bytelen;
  zkp_encryption_in_range_proof_to_bytes(NULL, &psi_enc_bytelen, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 0);

  uint64_t send_bytes_len =  psi_enc_bytelen + 4*PAILLIER_MODULUS_BYTES;
  uint8_t *send_bytes = malloc(send_bytes_len);
  uint8_t *curr_send = send_bytes;

  scalar_to_bytes(&curr_send, 2*PAILLIER_MODULUS_BYTES, preda->K, 1);
  scalar_to_bytes(&curr_send, 2*PAILLIER_MODULUS_BYTES, preda->G, 1);

  uint8_t *curr_send_pos_j = curr_send;

  zkp_encryption_in_range_t *zkp_enc_temp = zkp_encryption_in_range_new();

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    curr_send = curr_send_pos_j;
    zkp_encryption_in_range_proof_to_bytes(&curr_send, &psi_enc_bytelen, preda->psi_enc_j[j], CALIGRAPHIC_I_ZKP_RANGE_BYTES, 1);

    curr_send -= psi_enc_bytelen;
    zkp_encryption_in_range_proof_from_bytes(zkp_enc_temp, &curr_send, &psi_enc_bytelen, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 1);
    
    printf("A %d [%d]\n", scalar_equal(zkp_enc_temp->proof.A,     preda->psi_enc_j[j]->proof.A), BN_num_bits(preda->psi_enc_j[j]->proof.A));
    printf("C %d [%d]\n", scalar_equal(zkp_enc_temp->proof.C,     preda->psi_enc_j[j]->proof.C), BN_num_bits(preda->psi_enc_j[j]->proof.C));
    printf("S %d [%d]\n", scalar_equal(zkp_enc_temp->proof.S,     preda->psi_enc_j[j]->proof.S), BN_num_bits(preda->psi_enc_j[j]->proof.S));
    printf("z_1 %d [%d]\n", scalar_equal(zkp_enc_temp->proof.z_1, preda->psi_enc_j[j]->proof.z_1), BN_num_bits(preda->psi_enc_j[j]->proof.z_1));
    printf("z_2 %d [%d]\n", scalar_equal(zkp_enc_temp->proof.z_2, preda->psi_enc_j[j]->proof.z_2), BN_num_bits(preda->psi_enc_j[j]->proof.z_2));
    printf("z_3 %d [%d]\n", scalar_equal(zkp_enc_temp->proof.z_3, preda->psi_enc_j[j]->proof.z_3), BN_num_bits(preda->psi_enc_j[j]->proof.z_3));
    
    zkp_enc_temp->public.paillier_pub = party->paillier_pub[party->index];
    zkp_enc_temp->public.rped_pub = party->rped_pub[j];
    zkp_enc_temp->public.G = party->ec;
    zkp_enc_temp->public.K = preda->K;
    zkp_enc_temp->public.k_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    zkp_enc_temp->secret.k = preda->k;
    zkp_enc_temp->secret.rho = preda->rho;
    printf("%d\n", zkp_encryption_in_range_verify(zkp_enc_temp, aux));
    printf("psi_enc_%lue%lu = ", j, party->index); printHexBytes("", curr_send - psi_enc_bytelen, psi_enc_bytelen, "\n", 1);

    assert(curr_send == send_bytes + send_bytes_len);

    cmp_comm_send_bytes(party->index, j, 31, send_bytes, send_bytes_len);
  }
  free(send_bytes);

  // Print

  printf("### Broadcast (K_i, G_i). Send (psi_enc_j) to each Party j.\t>>>\t%lu B, %lu ms\n", send_bytes_len, time_diff);

  printHexBytes("sid_hash = 0x", party->sid_hash, sizeof(hash_chunk), "\n", 0);
  printf("K_%lu = ", party->index); printBIGNUM("", preda->K, "\n");
  printf("G_%lu = ", party->index); printBIGNUM("", preda->G, "\n");
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    printf("# psi_enc_%lu = ...\n", j);
  }

  if (!PRINT_SECRETS) return;
  printf("k_%lu = ", party->index); printBIGNUM("", preda->k, "\n");
  printf("gamma_%lu = ", party->index); printBIGNUM("", preda->gamma, "\n");
  printf("rho_%lu = ", party->index); printBIGNUM("", preda->rho, "\n");
  printf("nu_%lu = ", party->index); printBIGNUM("", preda->nu, "\n");
}

// TODO: add broadcast of first round common values, and verify at round 3

void  cmp_presign_round_2_exec (cmp_party_t *party)
{
  printf("### Presign Phase, Round 2, Party %lu.\n", party->index);

  cmp_presign_data_t *preda = party->presign_data;

  // Receive payload

  uint64_t psi_enc_bytelen;
  zkp_encryption_in_range_proof_to_bytes(NULL, &psi_enc_bytelen, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 0);

  uint64_t recv_bytes_len =  psi_enc_bytelen + 4*PAILLIER_MODULUS_BYTES;
  uint8_t *recv_bytes = malloc(recv_bytes_len);
  uint8_t *curr_recv;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    cmp_comm_receive_bytes(j, party->index, 31, recv_bytes, recv_bytes_len);
    curr_recv = recv_bytes;

    scalar_from_bytes(preda->payload[j]->K, &curr_recv, 2*PAILLIER_MODULUS_BYTES, 1);
    scalar_from_bytes(preda->payload[j]->G, &curr_recv, 2*PAILLIER_MODULUS_BYTES, 1);
    printf("K_%lu = ", j); printBIGNUM("", preda->payload[j]->K, "\n");
    printf("G_%lu = ", j); printBIGNUM("", preda->payload[j]->G, "\n");

    printf("psi_enc_%lue%lu = 0x", party->index, j); printHexBytes("", curr_recv, psi_enc_bytelen, "\n", 1);
    preda->payload[j]->psi_enc->public.paillier_pub = party->paillier_pub[j];
    preda->payload[j]->psi_enc->public.rped_pub = party->rped_pub[party->index];
    preda->payload[j]->psi_enc->public.G = party->ec;
    preda->payload[j]->psi_enc->public.K = preda->payload[j]->K;
    preda->payload[j]->psi_enc->public.k_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    zkp_encryption_in_range_proof_from_bytes(preda->payload[j]->psi_enc, &curr_recv, &psi_enc_bytelen, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 1);

    assert(curr_recv == recv_bytes + recv_bytes_len);
  }
  free(recv_bytes);

  // Execute Round

  clock_t time_start = clock();
  uint64_t time_diff;

  int *verified_psi_enc = calloc(party->num_parties, sizeof(int));

  // Echo broadcast - Send hash of all K_j,G_j
  uint8_t *temp_bytes = malloc(PAILLIER_MODULUS_BYTES);

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t i = 0; i < party->num_parties; ++i)
  {
    scalar_to_bytes(&temp_bytes, PAILLIER_MODULUS_BYTES, preda->payload[i]->K, 0);
    SHA512_Update(&sha_ctx, temp_bytes, PAILLIER_MODULUS_BYTES);
    scalar_to_bytes(&temp_bytes, PAILLIER_MODULUS_BYTES, preda->payload[i]->G, 0);
    SHA512_Update(&sha_ctx, temp_bytes, PAILLIER_MODULUS_BYTES);
  }
  SHA512_Final(preda->echo_broadcast, &sha_ctx);
  free(temp_bytes);
  
  // Aux Info for ZKP (ssid, i)
  zkp_aux_info_t *aux = zkp_aux_info_new(sizeof(uint64_t) + sizeof(hash_chunk), NULL);
  uint64_t aux_pos = 0;
  zkp_aux_info_update_move(aux, &aux_pos, party->sid_hash, sizeof(hash_chunk));
  zkp_aux_info_update_move(aux, &aux_pos, &party->id, sizeof(uint64_t));          // update later for each partyu
  assert(aux->info_len == aux_pos);

  // Verify psi_enc received
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    zkp_aux_info_update(aux, sizeof(hash_chunk), &party->parties_ids[j], sizeof(uint64_t));
    printHexBytes("aux = 0x", aux->info, aux->info_len, "\n", 1);
    verified_psi_enc[j] = zkp_encryption_in_range_verify(preda->payload[j]->psi_enc, aux);

    if (verified_psi_enc[j] != 1)  printf("%sParty %lu: failed verification of psi_enc from Party %lu\n",ERR_STR, party->index, j);
  }
  free(verified_psi_enc);

  zkp_aux_info_update(aux, sizeof(hash_chunk), &party->id, sizeof(uint64_t));

  group_operation(preda->Gamma, NULL, party->ec_gen, preda->gamma, party->ec);

  // Executing MtA with relevant ZKP

  scalar_t r          = scalar_new();
  scalar_t s          = scalar_new();
  scalar_t temp_enc   = scalar_new();
  scalar_t beta_range = scalar_new();

  scalar_set_power_of_2(beta_range, 8*CALIGRAPHIC_J_ZKP_RANGE_BYTES);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;
    
    // Create ZKP Paillier homomorphic operation against Paillier commitment

    scalar_sample_in_range(preda->beta_j[j], beta_range, 0);
    scalar_make_plus_minus(preda->beta_j[j], beta_range);
    paillier_encryption_sample(r, party->paillier_pub[party->index]);
    paillier_encryption_encrypt(preda->F_j[j], preda->beta_j[j], r, party->paillier_pub[party->index]);

    // ARTICLE-MOD: using \beta (and not -\beta) for both F and affine operation (later will compute \alpha-\beta in summation)
    paillier_encryption_sample(s, party->paillier_pub[j]);
    paillier_encryption_encrypt(temp_enc, preda->beta_j[j], s, party->paillier_pub[j]);
    paillier_encryption_homomorphic(preda->D_j[j], preda->payload[j]->K, preda->gamma, temp_enc, party->paillier_pub[j]);

    preda->psi_affp_j[j]->public.paillier_pub_0 = party->paillier_pub[j];
    preda->psi_affp_j[j]->public.paillier_pub_1 = party->paillier_pub[party->index];
    preda->psi_affp_j[j]->public.rped_pub = party->rped_pub[j];
    preda->psi_affp_j[j]->public.C = preda->payload[j]->K;
    preda->psi_affp_j[j]->public.G = party->ec;
    preda->psi_affp_j[j]->public.D = preda->D_j[j];
    preda->psi_affp_j[j]->public.X = preda->G;
    preda->psi_affp_j[j]->public.Y = preda->F_j[j];
    preda->psi_affp_j[j]->public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    preda->psi_affp_j[j]->public.y_range_bytes = CALIGRAPHIC_J_ZKP_RANGE_BYTES;
    preda->psi_affp_j[j]->secret.x = preda->gamma;
    preda->psi_affp_j[j]->secret.y = preda->beta_j[j];
    preda->psi_affp_j[j]->secret.rho_x = preda->nu;
    preda->psi_affp_j[j]->secret.rho_y = r;
    preda->psi_affp_j[j]->secret.rho = s;
    zkp_operation_paillier_commitment_range_prove(preda->psi_affp_j[j], aux);

    // Create ZKP Paillier homomorphic operation against Group commitment

    scalar_sample_in_range(preda->betahat_j[j], beta_range, 0);
    scalar_make_plus_minus(preda->betahat_j[j], beta_range);
    paillier_encryption_sample(r, party->paillier_pub[party->index]);
    paillier_encryption_encrypt(preda->Fhat_j[j], preda->betahat_j[j], r, party->paillier_pub[party->index]);

    // ARTICLE-MOD: using \betahat (and not -\betahat) for both F and affine operation (later will compute \alphahat-\betahat in summation)
    paillier_encryption_sample(s, party->paillier_pub[j]);
    paillier_encryption_encrypt(temp_enc, preda->betahat_j[j], s, party->paillier_pub[j]);
    paillier_encryption_homomorphic(preda->Dhat_j[j], preda->payload[j]->K, party->secret_x, temp_enc, party->paillier_pub[j]);

    preda->psi_affg_j[j]->public.paillier_pub_0 = party->paillier_pub[j];
    preda->psi_affg_j[j]->public.paillier_pub_1 = party->paillier_pub[party->index];
    preda->psi_affg_j[j]->public.rped_pub = party->rped_pub[j];
    preda->psi_affg_j[j]->public.G = party->ec;
    preda->psi_affg_j[j]->public.g = party->ec_gen;
    preda->psi_affg_j[j]->public.C = preda->payload[j]->K;
    preda->psi_affg_j[j]->public.D = preda->Dhat_j[j];
    preda->psi_affg_j[j]->public.X = party->public_X[party->index];
    preda->psi_affg_j[j]->public.Y = preda->Fhat_j[j];
    preda->psi_affg_j[j]->public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    preda->psi_affg_j[j]->public.y_range_bytes = CALIGRAPHIC_J_ZKP_RANGE_BYTES;
    preda->psi_affg_j[j]->secret.x = party->secret_x;
    preda->psi_affg_j[j]->secret.y = preda->betahat_j[j];
    preda->psi_affg_j[j]->secret.rho_y = r;
    preda->psi_affg_j[j]->secret.rho = s;
    zkp_operation_group_commitment_range_prove(preda->psi_affg_j[j], aux);

    // Create group vs Paillier in range ZKP

    preda->psi_logG_j[j]->public.paillier_pub = party->paillier_pub[party->index];
    preda->psi_logG_j[j]->public.rped_pub = party->rped_pub[j];
    preda->psi_logG_j[j]->public.G = party->ec;
    preda->psi_logG_j[j]->public.g = party->ec_gen;
    preda->psi_logG_j[j]->public.X = preda->Gamma;
    preda->psi_logG_j[j]->public.C = preda->G;
    preda->psi_logG_j[j]->public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    preda->psi_logG_j[j]->secret.x = preda->gamma;
    preda->psi_logG_j[j]->secret.rho = preda->nu;
    zkp_group_vs_paillier_range_prove(preda->psi_logG_j[j], aux);
  }
  zkp_aux_info_free(aux);
  scalar_free(beta_range);
  scalar_free(temp_enc);
  scalar_free(r);
  scalar_free(s);

  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  preda->run_time += time_diff;

  // Send Payload

  uint64_t psi_affp_bytes;
  uint64_t psi_affg_bytes;
  uint64_t psi_logG_bytes;
  zkp_operation_paillier_commitment_range_proof_to_bytes(NULL, &psi_affp_bytes, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES, 0);
  zkp_operation_group_commitment_range_proof_to_bytes(NULL, &psi_affg_bytes, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES, 0);
  zkp_group_vs_paillier_range_proof_to_bytes(NULL, &psi_logG_bytes, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 0);

  uint64_t send_bytes_len =  (party->num_parties-1) * ( 8*PAILLIER_MODULUS_BYTES + psi_affp_bytes + psi_affg_bytes + psi_logG_bytes) + GROUP_ELEMENT_BYTES; 
  uint8_t *send_bytes = malloc(send_bytes_len);
  uint8_t *curr_send = send_bytes;

  group_elem_to_bytes(&curr_send, GROUP_ELEMENT_BYTES, preda->Gamma, party->ec, 1);

  uint8_t *curr_send_pos_j = curr_send;
  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    curr_send = curr_send_pos_j;
    scalar_to_bytes(&curr_send, 2*PAILLIER_MODULUS_BYTES, preda->D_j[j], 1);
    scalar_to_bytes(&curr_send, 2*PAILLIER_MODULUS_BYTES, preda->F_j[j], 1);
    scalar_to_bytes(&curr_send, 2*PAILLIER_MODULUS_BYTES, preda->Dhat_j[j], 1);
    scalar_to_bytes(&curr_send, 2*PAILLIER_MODULUS_BYTES, preda->Fhat_j[j], 1);

    zkp_operation_paillier_commitment_range_proof_to_bytes(&curr_send, &psi_affp_bytes, preda->psi_affp_j[j], CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES, 1);
    zkp_operation_group_commitment_range_proof_to_bytes(&curr_send, &psi_affg_bytes, preda->psi_affg_j[j], CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES, 1);
    zkp_group_vs_paillier_range_proof_to_bytes(&curr_send, &psi_logG_bytes, preda->psi_logG_j[j], CALIGRAPHIC_I_ZKP_RANGE_BYTES, 1);

    assert(curr_send == send_bytes + send_bytes_len);

    cmp_comm_send_bytes(party->index, j, 32, send_bytes, send_bytes_len);
  }
  free(send_bytes);

  // Print

  printf("### Send (Gamma_i, D_{j,i}, F_{j,i}, D^_{j,i}, F^_{j,i}, psi_affp_j, psi_affg_j, psi_logG_j) to each Party j.\t>>>\t%lu B, %lu ms\n", send_bytes_len, time_diff);
  
  printf("Gamma_%lu = ", party->index); printECPOINT("", preda->Gamma, party->ec, "\n", 1);
  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    printf("D_%lue%lu = ", j, party->index); printBIGNUM("", preda->D_j[j], "\n");
    printf("F_%lue%lu = ", j, party->index); printBIGNUM("", preda->F_j[j],  "\n");
    printf("Dhat_%lue%lu = ", j, party->index); printBIGNUM("", preda->Dhat_j[j], "\n");
    printf("Fhat_%lue%lu = ", j, party->index); printBIGNUM("", preda->Fhat_j[j],  "\n");
    printf("# psi_affp_%lu = ...\n", j);
    printf("# psi_affg_%lu = ...\n", j);
    printf("# psi_logG_%lu = ...\n", j);
  }

  if (!PRINT_SECRETS) return;
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    printf("beta_%lue%lu = ", party->index, j); printBIGNUM("", preda->beta_j[j], "\n");
    printf("betahat_%lue%lu = ", party->index, j); printBIGNUM("", preda->betahat_j[j],  "\n");
  }
}

void  cmp_presign_round_3_exec (cmp_party_t *party)
{
  printf("### Presign Phase, Round 3, Party %lu.\n", party->index);

  cmp_presign_data_t *preda = party->presign_data;

  // Receive payload

  uint64_t psi_affp_bytes;
  uint64_t psi_affg_bytes;
  uint64_t psi_logG_bytes;
  zkp_operation_paillier_commitment_range_proof_to_bytes(NULL, &psi_affp_bytes, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES, 0);
  zkp_operation_group_commitment_range_proof_to_bytes(NULL, &psi_affg_bytes, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES, 0);
  zkp_group_vs_paillier_range_proof_to_bytes(NULL, &psi_logG_bytes, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 0);

  uint64_t recv_bytes_len =  (party->num_parties-1) * ( 8*PAILLIER_MODULUS_BYTES + psi_affp_bytes + psi_affg_bytes + psi_logG_bytes) + GROUP_ELEMENT_BYTES; 
  uint8_t *recv_bytes = malloc(recv_bytes_len);
  uint8_t *curr_recv;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    cmp_comm_receive_bytes(j, party->index, 32, recv_bytes, recv_bytes_len);
    curr_recv = recv_bytes;

    group_elem_from_bytes(preda->payload[j]->Gamma, &curr_recv, GROUP_ELEMENT_BYTES, party->ec, 1);
    scalar_from_bytes(preda->payload[j]->D, &curr_recv, 2*PAILLIER_MODULUS_BYTES, 1);
    scalar_from_bytes(preda->payload[j]->F, &curr_recv, 2*PAILLIER_MODULUS_BYTES, 1);
    scalar_from_bytes(preda->payload[j]->Dhat, &curr_recv, 2*PAILLIER_MODULUS_BYTES, 1);
    scalar_from_bytes(preda->payload[j]->Fhat, &curr_recv, 2*PAILLIER_MODULUS_BYTES, 1);

    preda->payload[j]->psi_affp->public.paillier_pub_0 = party->paillier_pub[party->index];
    preda->payload[j]->psi_affp->public.paillier_pub_1 = party->paillier_pub[j];
    preda->payload[j]->psi_affp->public.rped_pub = party->rped_pub[party->index];
    preda->payload[j]->psi_affp->public.C = preda->K;
    preda->payload[j]->psi_affp->public.G = party->ec;
    preda->payload[j]->psi_affp->public.D = preda->payload[j]->D;
    preda->payload[j]->psi_affp->public.X = preda->G;
    preda->payload[j]->psi_affp->public.Y = preda->payload[j]->F;
    preda->payload[j]->psi_affp->public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    preda->payload[j]->psi_affp->public.y_range_bytes = CALIGRAPHIC_J_ZKP_RANGE_BYTES;
    zkp_operation_paillier_commitment_range_proof_from_bytes(preda->payload[j]->psi_affp, &curr_recv, &psi_affp_bytes, CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES, 1);

    preda->payload[j]->psi_affg->public.paillier_pub_0 = party->paillier_pub[party->index];
    preda->payload[j]->psi_affg->public.paillier_pub_1 = party->paillier_pub[j];
    preda->payload[j]->psi_affg->public.rped_pub = party->rped_pub[j];
    preda->payload[j]->psi_affg->public.G = party->ec;
    preda->payload[j]->psi_affg->public.g = party->ec_gen;
    preda->payload[j]->psi_affg->public.C = preda->K;
    preda->payload[j]->psi_affg->public.D = preda->payload[j]->Dhat;
    preda->payload[j]->psi_affg->public.X = party->public_X[j];
    preda->payload[j]->psi_affg->public.Y = preda->payload[j]->Fhat;
    preda->payload[j]->psi_affg->public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    preda->payload[j]->psi_affg->public.y_range_bytes = CALIGRAPHIC_J_ZKP_RANGE_BYTES;
    zkp_operation_group_commitment_range_proof_from_bytes(preda->payload[j]->psi_affg, &curr_recv, &psi_affg_bytes, CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES, 1);

    preda->payload[j]->psi_logG->public.paillier_pub = party->paillier_pub[j];
    preda->payload[j]->psi_logG->public.rped_pub = party->rped_pub[party->index];
    preda->payload[j]->psi_logG->public.G = party->ec;
    preda->payload[j]->psi_logG->public.g = party->ec_gen;
    preda->payload[j]->psi_logG->public.X = preda->payload[j]->Gamma;
    preda->payload[j]->psi_logG->public.C = preda->payload[j]->G;
    preda->payload[j]->psi_logG->public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    zkp_group_vs_paillier_range_proof_from_bytes(preda->payload[j]->psi_logG, &curr_recv, &psi_logG_bytes, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 1);

    assert(curr_recv == recv_bytes + recv_bytes_len);
  }
  free(recv_bytes);

  // Execute round

  clock_t time_start = clock();
  uint64_t time_diff;

  // Verify ZKP

  // Aux Info for ZKP (ssid, i)
  zkp_aux_info_t *aux = zkp_aux_info_new(sizeof(uint64_t) + sizeof(hash_chunk), NULL);
  uint64_t aux_pos = 0;
  zkp_aux_info_update_move(aux, &aux_pos, party->sid_hash, sizeof(hash_chunk));
  zkp_aux_info_update_move(aux, &aux_pos, &party->id, sizeof(uint64_t));          // update later for each partyu
  assert(aux->info_len == aux_pos);

  int *verified_psi_affp = calloc(party->num_parties, sizeof(int));
  int *verified_psi_affg = calloc(party->num_parties, sizeof(int));
  int *verified_psi_logG = calloc(party->num_parties, sizeof(int));

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    zkp_aux_info_update(aux, sizeof(hash_chunk), &party->parties_ids[j], sizeof(uint64_t));

    verified_psi_affp[j] = zkp_operation_paillier_commitment_range_verify(preda->payload[j]->psi_affp, aux);
    verified_psi_affg[j] = zkp_operation_group_commitment_range_verify(preda->payload[j]->psi_affg, aux);
    verified_psi_logG[j] = zkp_group_vs_paillier_range_verify(preda->payload[j]->psi_logG, aux);

    if (verified_psi_affp[j] != 1) printf("%sParty %lu: failed verification of psi_affp from Party %lu\n",ERR_STR, party->index, j);
    if (verified_psi_affg[j] != 1) printf("%sParty %lu: failed verification of psi_affg from Party %lu\n",ERR_STR, party->index, j);
    if (verified_psi_logG[j] != 1) printf("%sParty %lu: failed verification of psi_logG from Party %lu\n",ERR_STR, party->index, j);
  }

  free(verified_psi_affp);
  free(verified_psi_affg);
  free(verified_psi_logG);

  group_operation(preda->combined_Gamma, NULL, NULL, NULL, party->ec);
  for (uint64_t i = 0; i < party->num_parties; ++i) 
  {
    group_operation(preda->combined_Gamma, preda->combined_Gamma, preda->payload[i]->Gamma, NULL, party->ec);
  }
  
  group_operation(preda->Delta, NULL, preda->combined_Gamma, preda->k, party->ec);

  zkp_aux_info_update(aux, sizeof(hash_chunk), &party->id, sizeof(uint64_t));

  scalar_t alpha_j = scalar_new();

  scalar_mul(preda->delta, preda->gamma, preda->k, party->ec_order);
  scalar_mul(preda->chi, party->secret_x, preda->k, party->ec_order);

  for (uint64_t j = 0; j < party->num_parties; ++j) 
  {
    if (j == party->index) continue;
    
    // Compute delta_i
    paillier_encryption_decrypt(alpha_j, preda->payload[j]->D, party->paillier_priv);
    scalar_make_plus_minus(alpha_j, party->paillier_pub[party->index]->N);
    scalar_add(preda->delta, preda->delta, alpha_j, party->ec_order);
    scalar_sub(preda->delta, preda->delta, preda->beta_j[j], party->ec_order);

    // Compute chi_i
    paillier_encryption_decrypt(alpha_j, preda->payload[j]->Dhat, party->paillier_priv);
    scalar_make_plus_minus(alpha_j, party->paillier_pub[party->index]->N);
    scalar_add(preda->chi, preda->chi, alpha_j, party->ec_order);
    scalar_sub(preda->chi, preda->chi, preda->betahat_j[j], party->ec_order);

    // Create Group vs Paillier range ZKP for K against Gamma and Delta

    preda->psi_logK_j[j]->public.paillier_pub = party->paillier_pub[party->index];
    preda->psi_logK_j[j]->public.rped_pub = party->rped_pub[j];
    preda->psi_logK_j[j]->public.G = party->ec;
    preda->psi_logK_j[j]->public.g = preda->combined_Gamma;
    preda->psi_logK_j[j]->public.X = preda->Delta;
    preda->psi_logK_j[j]->public.C = preda->K;
    preda->psi_logK_j[j]->public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    preda->psi_logK_j[j]->secret.x = preda->k;
    preda->psi_logK_j[j]->secret.rho = preda->rho;
    zkp_group_vs_paillier_range_prove(preda->psi_logK_j[j], aux);
  }
  zkp_aux_info_free(aux);
  scalar_free(alpha_j);
  
  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  preda->run_time += time_diff;

  // Send payload

  uint64_t psi_logK_bytes;
  zkp_group_vs_paillier_range_proof_to_bytes(NULL, &psi_logK_bytes, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 0);

  uint64_t send_bytes_len = GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES + (party->num_parties-1) * psi_logK_bytes; 
  uint8_t *send_bytes = malloc(send_bytes_len);
  uint8_t *curr_send = send_bytes;

  scalar_to_bytes(&curr_send, GROUP_ORDER_BYTES, preda->delta, 1);
  group_elem_to_bytes(&curr_send, GROUP_ELEMENT_BYTES, preda->Delta, party->ec, 1);

  uint8_t *curr_send_pos_j = curr_send;
  
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    curr_send = curr_send_pos_j;
    zkp_group_vs_paillier_range_proof_to_bytes(&curr_send, &psi_logK_bytes, preda->psi_logK_j[j], CALIGRAPHIC_I_ZKP_RANGE_BYTES, 1);
    assert(curr_send == send_bytes + send_bytes_len);

    cmp_comm_send_bytes(party->index, j, 32, send_bytes, send_bytes_len);
  }
  free(send_bytes);

  // Print

  printf("### Publish (delta_i, Delta_i, psi_logK_j)).\t>>>\t%lu B, %lu ms\n", send_bytes_len, time_diff);

  if (!PRINT_SECRETS) return;
  printf("delta_%lu = ", party->index); printBIGNUM("", preda->delta, "\n");
  printf("Delta_%lu = ", party->index); printECPOINT("", preda->Delta, party->ec, "\n", 1);
  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    printf("# psi_logK_%lu = ...\n", j);
  }
}

void  cmp_presign_final_exec (cmp_party_t *party)
{
    printf("### Presign Phase, Finalization Round, Party %lu.\n", party->index);

  cmp_presign_data_t *preda = party->presign_data;

  // Receive payload

  uint64_t psi_logK_bytes;
  zkp_group_vs_paillier_range_proof_to_bytes(NULL, &psi_logK_bytes, NULL, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 0);

  uint64_t recv_bytes_len =  (party->num_parties-1) * (psi_logK_bytes) + GROUP_ORDER_BYTES + GROUP_ELEMENT_BYTES; 
  uint8_t *recv_bytes = malloc(recv_bytes_len);
  uint8_t *curr_recv;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue;

    cmp_comm_receive_bytes(j, party->index, 32, recv_bytes, recv_bytes_len);
    curr_recv = recv_bytes;

    scalar_from_bytes(preda->payload[j]->delta, &curr_recv, GROUP_ORDER_BYTES, 1);
    group_elem_from_bytes(preda->payload[j]->Delta, &curr_recv, GROUP_ELEMENT_BYTES, party->ec, 1);

    preda->payload[j]->psi_logK->public.paillier_pub = party->paillier_pub[j];
    preda->payload[j]->psi_logK->public.rped_pub = party->rped_pub[party->index];
    preda->payload[j]->psi_logK->public.G = party->ec;
    preda->payload[j]->psi_logK->public.g = party->ec_gen;
    preda->payload[j]->psi_logK->public.X = preda->payload[j]->Gamma;
    preda->payload[j]->psi_logK->public.C = preda->payload[j]->G;
    preda->payload[j]->psi_logK->public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
    zkp_group_vs_paillier_range_proof_from_bytes(preda->payload[j]->psi_logK, &curr_recv, &psi_logK_bytes, CALIGRAPHIC_I_ZKP_RANGE_BYTES, 1);

    assert(curr_recv == recv_bytes + recv_bytes_len);
  }
  free(recv_bytes);

  // Execute round

  clock_t time_start = clock();
  uint64_t time_diff;
  
  // Verify ZKP

  // Aux Info for ZKP (ssid, i)
  zkp_aux_info_t *aux = zkp_aux_info_new(sizeof(uint64_t) + sizeof(hash_chunk), NULL);
  uint64_t aux_pos = 0;
  zkp_aux_info_update_move(aux, &aux_pos, party->sid_hash, sizeof(hash_chunk));
  zkp_aux_info_update_move(aux, &aux_pos, &party->id, sizeof(uint64_t));          // update later for each partyu
  assert(aux->info_len == aux_pos);

  int *verified_psi_logK = calloc(party->num_parties, sizeof(int));
  int verified_delta;

  for (uint64_t j = 0; j < party->num_parties; ++j)
  {
    if (j == party->index) continue; 

    zkp_aux_info_update(aux, sizeof(hash_chunk), &party->parties_ids[j], sizeof(uint64_t));
    verified_psi_logK[j] = zkp_group_vs_paillier_range_verify(preda->payload[j]->psi_logK, aux);

    if (verified_psi_logK[j] != 1) printf("%sParty %lu: failed verification of psi_logK from Party %lu\n",ERR_STR, party->index, j);
  }
  zkp_aux_info_free(aux);
  free(verified_psi_logK);

  scalar_t combined_delta = scalar_new();
  gr_elem_t gen_to_delta = group_elem_new(party->ec);
  gr_elem_t combined_Delta = group_elem_new(party->ec);
  
  scalar_set_ul(combined_delta, 0);
  group_operation(combined_Delta, NULL, NULL, NULL, party->ec);
  for (uint64_t i = 0; i < party->num_parties; ++i) 
  {
    scalar_add(combined_delta, combined_delta, preda->payload[i]->delta, party->ec_order);
    group_operation(combined_Delta, combined_Delta, preda->payload[i]->Delta, NULL, party->ec);
  }
  group_operation(gen_to_delta, NULL, party->ec_gen, combined_delta, party->ec);
  assert(PAILLIER_MODULUS_BYTES >= CALIGRAPHIC_J_ZKP_RANGE_BYTES);    // The following ZKP is valid when N is bigger then beta's range)
  verified_delta = group_elem_equal(gen_to_delta, combined_Delta, party->ec);

  if (verified_delta != 1) printf("%sParty %lu: failed equality of g^{delta} = combined_Delta\n",ERR_STR, party->index);

  scalar_inv(combined_delta, combined_delta, party->ec_order);
  group_operation(party->R, NULL, preda->combined_Gamma, combined_delta, party->ec);
  
  scalar_free(combined_delta);
  group_elem_free(combined_Delta);
  group_elem_free(gen_to_delta);

  scalar_copy(party->k, preda->k);
  scalar_copy(party->chi, preda->chi);
  
  time_diff = (clock() - time_start) * 1000 /CLOCKS_PER_SEC;
  preda->run_time += time_diff;
  
  // Print 

  printf("### Store (R, k_i, chi_i).\t>>>\t%d B, %lu ms\n",  2*GROUP_ORDER_BYTES + GROUP_ELEMENT_BYTES, time_diff);
  printf("R = "); printECPOINT("", party->R, party->ec, "\n", 1);  

  if (!PRINT_SECRETS) return;
  printf("k_%lu = ", party->index); printBIGNUM("", party->k, "\n");
  printf("chi_%lu = ", party->index); printBIGNUM("", party->chi, "\n");
}

void cmp_signature_share (scalar_t r, scalar_t sigma, const cmp_party_t *party, const scalar_t msg)
{
  scalar_t first_term = scalar_new();
  scalar_t second_term = scalar_new();

  group_elem_get_x(r, party->R, party->ec, party->ec_order);
  
  scalar_mul(first_term, party->k, msg, party->ec_order);
  scalar_mul(second_term, party->chi, r, party->ec_order);
  scalar_add(sigma, first_term, second_term, party->ec_order);

  scalar_free(first_term);
  scalar_free(second_term);
}