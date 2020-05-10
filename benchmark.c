#include "primitives.h"
#include "common.h"
#include "tests.h"

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

void time_paillier_generate_keys(uint64_t reps)
{
  paillier_private_key_t priv;
  int priv_prime_bits = 0;

  start = clock();  

  for (uint64_t i = 0; i < reps; ++i)
  {
    paillier_encryption_generate_key(&priv);
    priv_prime_bits = BN_num_bits(priv.p);
    paillier_encryption_free_keys(&priv, NULL);
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
    paillier_encryption_encrypt(pub, plaintext, randomness, ciphertext);
  }

  //printf("plain = %s\nrandom = %s\ncipher = ", (plaintext), BN_bn2dec(randomness), BN_bn2dec(ciphertext), "\n");

  diff = clock() - start;
  printf("# %lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);

  scalar_free(plaintext);
  scalar_free(ciphertext);
  scalar_free(randomness);
}

int main()
{
  start = clock();
  
  paillier_private_key_t *priv = paillier_encryption_generate_key();

  diff = clock() - start;

  printf("# paillier key\n");
  printBIGNUM("p = ", (priv->p), "\n");
  printBIGNUM("q = ", (priv->q), "\n");
  printBIGNUM("paillier_lambda = ", (priv->lambda), "\n");
  printBIGNUM("nmu = ", (priv->mu), "\n");
  printBIGNUM("N = ", (priv->pub.N), "\n");
  printBIGNUM("N2 = ", (priv->pub.N2), "\n");

  printf("# generating single paillier (%d-bits primes) priv/pub key pair: %lu msec\n", BN_num_bits(priv->p), diff * 1000/ CLOCKS_PER_SEC);

  test_paillier_operations(priv);

  time_paillier_encrypt(100, &priv->pub, 0, 0);

  test_ring_pedersen(priv->p, priv->q);

  test_fiat_shamir(100, 100);

  test_scalars(priv->p, PAILLIER_FACTOR_BYTES);
  test_scalars(priv->pub.N, PAILLIER_MODULUS_BYTES);
  test_scalars(priv->pub.N2, 2*PAILLIER_MODULUS_BYTES);

  paillier_encryption_free_keys(priv, NULL);

  test_group_elements();
}