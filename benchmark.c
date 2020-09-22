#include "primitives.h"
#include "common.h"
#include "tests.h"
#include "cmp_ecdsa_protocol.h"

#include <assert.h>
#include <time.h>
#include <openssl/sha.h>

clock_t start;
clock_t diff;

void time_sampling_scalars(uint64_t reps, const scalar_t range, int coprime)
{
  scalar_t alpha;

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    alpha = scalar_new();
    scalar_sample_in_range(alpha, range, coprime);
    //printf("alpha: ", (alphas[i]), "\n");
    scalar_free(alpha);
  }

  diff = clock() - start;
  printf("# sampling scalars (coprime: %d)\n%lu repetitions, time: %lu msec, avg: %f msec\n", coprime, reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
}

paillier_private_key_t *time_paillier_generate_keys(uint64_t paillier_modulus_bits)
{
  start = clock();
  
  paillier_private_key_t *priv = paillier_encryption_private_new();
  paillier_encryption_generate_private(priv, paillier_modulus_bits/2);

  diff = clock() - start;

  printf("# paillier key\n");
  printBIGNUM("paillier_phi_N = ", (priv->phi_N), "\n");
  printBIGNUM("p = ", (priv->p), "\n");
  printBIGNUM("q = ", (priv->q), "\n");
  printBIGNUM("nmu = ", (priv->mu), "\n");
  printBIGNUM("N = ", (priv->N), "\n");
  printBIGNUM("N2 = ", (priv->N2), "\n");

  printf("### generating single paillier (%d-bits modulus) priv/pub key pair: %lu msec\n", BN_num_bits(priv->N), diff * 1000/ CLOCKS_PER_SEC);

  return priv;
}

ring_pedersen_private_t *time_ring_pedersen_generate_param(uint64_t rped_modulus_bits)
{
  start = clock();
  
  ring_pedersen_private_t *priv = ring_pedersen_private_new();
  ring_pedersen_generate_private(priv, rped_modulus_bits/2);

  diff = clock() - start;

  printf("# ring Pedersen parameters\n");
  printBIGNUM("N = ", priv->N, "\n");
  printBIGNUM("phi_N = ",priv->phi_N, "\n");
  printBIGNUM("lambda ", priv->lam, "\n");
  printBIGNUM("s = ", priv->s, "\n");
  printBIGNUM("t = ", priv->t, "\n");

  printf("### generating single ring pedersen parameters (%d-bits modulus): %lu msec\n", BN_num_bits(priv->N), diff * 1000/ CLOCKS_PER_SEC);

  return priv;
}

void time_hashing(uint64_t reps, const uint8_t* data, uint64_t data_len)
{ 
  unsigned char digest[512];

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    SHA512_CTX sha_ctx;
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, data, data_len);
    SHA512_Final(digest, &sha_ctx);  
  }

  diff = clock() - start;

  printf("# Sha512 Digest\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
}

void time_paillier_encrypt(uint64_t reps, paillier_public_key_t *pub, unsigned long start_plain, unsigned long start_rand)
{ 
  printf("# Paillier Encryption\n");

  scalar_t plaintext = scalar_new();
  scalar_t ciphertext = scalar_new();
  scalar_t randomness = scalar_new();

  if (start_plain) BN_set_word(plaintext, start_plain);
  else scalar_sample_in_range(plaintext, pub->N, 0);
  if (start_rand) BN_set_word(randomness, start_rand);
  else scalar_sample_in_range(randomness, pub->N, 0);

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    BN_add_word(plaintext, 1);
    BN_add_word(randomness, 1);
    paillier_encryption_encrypt(ciphertext, plaintext, randomness, pub);
  }

  //printf("plain = %s\nrandom = %s\ncipher = ", (plaintext), BN_bn2dec(randomness), BN_bn2dec(ciphertext), "\n");

  diff = clock() - start;
  printf("# %lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);

  scalar_free(plaintext);
  scalar_free(ciphertext);
  scalar_free(randomness);
}

void time_bn_ctx(uint64_t reps)
{
  ec_group_t ec = ec_group_new();
  gr_elem_t el = group_elem_new(ec);
  //uint8_t el_bytes[GROUP_ELEMENT_BYTES];

  scalar_t a[10];
  for (uint64_t i = 0; i < 5; ++i)
  {
    a[i] = scalar_new();
    a[i+5] = scalar_new();
    scalar_sample_in_range(a[i], ec_group_order(ec), 0);
    BN_copy(a[i+5], a[i]);
  }

  BN_CTX **bn_ctx_arr = calloc(reps, sizeof(BN_CTX*));

  printf("# timing bn_ctx_secure_new + operation, each fresh\n");
  printBIGNUM("G * ", a[0], "\n");

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    bn_ctx_arr[i] = BN_CTX_secure_new();
    EC_POINT_mul(ec, el, a[0], NULL, NULL, bn_ctx_arr[i]);
    scalar_add(a[0], a[0], a[1], ec_group_order(ec));
  }

  diff = clock() - start;

  printf("# %lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);

  for (uint64_t i = 0; i < reps; ++i) BN_CTX_free(bn_ctx_arr[i]);
  free(bn_ctx_arr);
  
  printf("# timing single bn_ctx_secure_new + (operation repeating) \n");

  BN_copy(a[0], a[5]);

  start = clock();

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  for (uint64_t i = 0; i < reps; ++i)
  {
    EC_POINT_mul(ec, el, a[0], NULL, NULL, bn_ctx);
    scalar_add(a[0], a[0], a[1], ec_group_order(ec));
  }
  BN_CTX_free(bn_ctx);
  diff = clock() - start;
  
  printf("# %lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
  for (uint64_t i = 0; i < 10; ++i) scalar_free(a[i]);
  group_elem_free(el);
  ec_group_free(ec);
}

int main(int argc, char* argv[])
{ 
  int print_secrets = 0;
  uint64_t num_parties = 2;
  uint64_t party_index;

  uint64_t modulus_bits = 1024;

  if (argc >= 2)
  {
    if (strcmp(argv[1], "cmp") == 0) 
    {
      if (argc <= 2) goto USAGE;

      // Must have party index
      party_index = strtoul(argv[2], NULL, 10);

      // Testing the protocol 

      if (argc >= 4)
      {
        num_parties = strtoul(argv[3], NULL, 10);
        if (argc >= 5) print_secrets = strcmp(argv[4], "0") != 0;
      }

      printf("PAILLIER_MODULUS_BYTES = %u\n", PAILLIER_MODULUS_BYTES);
      printf("RING_PED_MODULUS_BYTES = %u\n", RING_PED_MODULUS_BYTES);
      printf("EPS_ZKP_SLACK_PARAMETER_BYTES = %u\n", EPS_ZKP_SLACK_PARAMETER_BYTES);
      printf("ELL_ZKP_RANGE_PARAMETER_BYTES = %u\n", ELL_ZKP_RANGE_PARAMETER_BYTES);
      printf("CALIGRAPHIC_I_ZKP_RANGE_BYTES = %u\n", CALIGRAPHIC_I_ZKP_RANGE_BYTES);
      printf("CALIGRAPHIC_J_ZKP_RANGE_BYTES = %u\n", CALIGRAPHIC_J_ZKP_RANGE_BYTES);
      // printf("ZKP_PAILLIER_BLUM_MODULUS_PROOF_BYTES = %lu\n", zkp_paillier_blum_proof_bytes());
      // printf("ZKP_RING_PEDERSEN_PARAM_PROOF_BYTES = %lu\n", zkp_ring_pedersen_param_proof_bytes());
      // printf("ZKP_SCHNORR_PROOF_BYTES = %lu\n", zkp_schnorr_proof_bytes());
      // printf("ZKP_GROUP_VS_PAILLIER_PROOF_BYTES = %lu\n", zkp_group_vs_paillier_range_proof_bytes(CALIGRAPHIC_I_ZKP_RANGE_BYTES));
      // printf("ZKP_OPERATION_GROUP_COMMITMENT_PROOF_BYTES = %lu\n", zkp_oper_group_commit_range_proof_bytes(CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES));
      // printf("ZKP_OPERATION_PAILLIER_COMMITMENT_PROOF_BYTES = %lu\n", zkp_oper_paillier_commit_range_proof_bytes(CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES));

      printf("\n### Party %lu executing protocol, out of %lu parties\n", party_index, num_parties);
      
      test_protocol(party_index, num_parties, print_secrets);

      return 0;
    }
    else if (strcmp(argv[1], "paillier") == 0)
    {
      if (argc >= 3) modulus_bits = strtoul(argv[2], NULL, 10);

      paillier_private_key_t *priv = time_paillier_generate_keys(modulus_bits);

      test_paillier_operations(priv);

      // time_paillier_encrypt(100, &priv->pub, 0, 0);

      paillier_encryption_free_keys(priv, NULL);

      return 0;
    }
    else if (strcmp(argv[1], "pedersen") == 0)
    {
      if (argc >= 3) modulus_bits = strtoul(argv[2], NULL, 10);

      ring_pedersen_private_t *priv = time_ring_pedersen_generate_param(modulus_bits);

      ring_pedersen_free_param(priv, NULL);
    }
    else if (strcmp(argv[1], "zkp") == 0)
    {
      paillier_private_key_t *paillier_priv = paillier_encryption_private_new();
      paillier_public_key_t  *paillier_pub = paillier_encryption_public_new();
      ring_pedersen_private_t *rped_priv = ring_pedersen_private_new();
      ring_pedersen_public_t  *rped_pub = ring_pedersen_public_new();

      paillier_encryption_generate_private(paillier_priv, 4 * PAILLIER_MODULUS_BYTES);
      paillier_encryption_copy_keys(NULL, paillier_pub, paillier_priv, NULL);
      ring_pedersen_generate_private(rped_priv, 4 * RING_PED_MODULUS_BYTES);
      ring_pedersen_copy_param(NULL, rped_pub, rped_priv, NULL);

      test_zkp_encryption_in_range(paillier_pub, rped_pub, CALIGRAPHIC_I_ZKP_RANGE_BYTES);
    
      paillier_encryption_free_keys(paillier_priv, paillier_pub);
      ring_pedersen_free_param(rped_priv, rped_pub);
    }
    else if (strcmp(argv[1], "write") == 0)
    {
      int from_index = strtoul(argv[2], NULL, 10);
      int to_index = strtoul(argv[3], NULL, 10);
      
      cmp_comm_send_bytes(from_index, to_index, 1, (const uint8_t*) argv[4], strlen(argv[4]));

      return 0;
    }
    else if (strcmp(argv[1], "read") == 0)
    {
      int from_index = strtoul(argv[2], NULL, 10);
      int to_index = strtoul(argv[3], NULL, 10);
      
      uint8_t buffer[3];
      cmp_comm_receive_bytes(from_index, to_index, 1, buffer, sizeof(buffer));
      printHexBytes("read: ", buffer, 3, "\n", 0);

      return 0;
    }
  }

USAGE:
  printf("\nUsage options:\n");
  printf("%s cmp <party_index> <num_parties (%lu)> [print_secrets (%d)]\n", argv[0], num_parties, print_secrets); 
  printf("%s paillier <modulus_bits (%lu)>\n", argv[0], modulus_bits); 
  //printf("%s\n zkp <paillier_modulus_bits (%ul)>\n", argv[0], modulus_bits); 

  return 1;
}