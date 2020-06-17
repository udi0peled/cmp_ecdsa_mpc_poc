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

void time_paillier_generate_keys(uint64_t reps, uint64_t paillier_modulus_bits)
{
  paillier_private_key_t *priv;
  int priv_prime_bits = 0;

  start = clock();  

  for (uint64_t i = 0; i < reps; ++i)
  {
    priv = paillier_encryption_generate_key(paillier_modulus_bits/2);
    priv_prime_bits = BN_num_bits(priv->p);
    paillier_encryption_free_keys(priv, NULL);
  }

  diff = clock() - start;
  printf("# generating paillier (%d-bits primes) safe keys\n%lu repetitions, time: %lu msec, avg: %f msec\n", priv_prime_bits, reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
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
    // group_elem_to_bytes(el_bytes, sizeof(el_bytes), el, ec);
    // printHexBytes("# el = ", el_bytes, sizeof(el_bytes), "\n");
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
    // group_elem_to_bytes(el_bytes, sizeof(el_bytes), el, ec);
    // printHexBytes("# el = ", el_bytes, sizeof(el_bytes), "\n");

  }
  BN_CTX_free(bn_ctx);
  diff = clock() - start;
  
  printf("# %lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
  for (uint64_t i = 0; i < 10; ++i) scalar_free(a[i]);
  group_elem_free(el);
  ec_group_free(ec);
}

int main()
{ 
  printf("PAILLIER_MODULUS_BYTES = %u\n", PAILLIER_MODULUS_BYTES);
  printf("RING_PED_MODULUS_BYTES = %u\n", RING_PED_MODULUS_BYTES);
  printf("ZKP_PAILLIER_BLUM_MODULUS_PROOF_BYTES = %lu\n", zkp_paillier_blum_proof_bytes());
  printf("ZKP_RING_PEDERSEN_PARAM_PROOF_BYTES = %lu\n", zkp_ring_pedersen_param_proof_bytes());
  printf("ZKP_SCHNORR_PROOF_BYTES = %lu\n", zkp_schnorr_proof_bytes());
  printf("ZKP_GROUP_VS_PAILLIER_PROOF_BYTES = %lu\n", zkp_group_vs_paillier_range_proof_bytes(CALIGRAPHIC_I_ZKP_RANGE_BYTES));
  printf("ZKP_OPERATION_GROUP_COMMITMENT_PROOF_BYTES = %lu\n", zkp_operation_group_commitment_range_proof_bytes(CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES));
  printf("ZKP_OPERATION_PAILLIER_COMMITMENT_PROOF_BYTES = %lu\n", zkp_operation_paillier_commitment_range_proof_bytes(CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES));
  
  start = clock();
  
  paillier_private_key_t *priv = paillier_encryption_generate_key(4*PAILLIER_MODULUS_BYTES);

  diff = clock() - start;

  printf("# paillier key\n");
  printBIGNUM("p = ", (priv->p), "\n");
  printBIGNUM("q = ", (priv->q), "\n");
  printBIGNUM("paillier_phi_N = ", (priv->phi_N), "\n");
  printBIGNUM("nmu = ", (priv->mu), "\n");
  printBIGNUM("N = ", (priv->pub.N), "\n");
  printBIGNUM("N2 = ", (priv->pub.N2), "\n");

  printf("# generating single paillier (%d-bits primes) priv/pub key pair: %lu msec\n", BN_num_bits(priv->p), diff * 1000/ CLOCKS_PER_SEC);

  // test_paillier_operations(priv);

  // time_paillier_encrypt(100, &priv->pub, 0, 0);

  // test_ring_pedersen(priv->p, priv->q);

  // test_fiat_shamir(100, 100);

  //test_scalars(priv->p, PAILLIER_MODULUS_BYTES/2);
  //test_scalars(priv->pub.N, PAILLIER_MODULUS_BYTES);
  // test_scalars(priv->pub.N2, 2*PAILLIER_MODULUS_BYTES);

  //test_group_elements();

  //time_bn_ctx(1000);

  ring_pedersen_private_t *rped_priv = ring_pedersen_generate_param(priv->p, priv->q);
  // test_zkp_schnorr();

  // test_zkp_encryption_in_range(&priv->pub, &rped_priv->pub);

  paillier_encryption_free_keys(priv, NULL);
  ring_pedersen_free_param(rped_priv,NULL);

  test_protocol();
}