#include "nikmak_ecdsa_mpc_poc.h"
#include <assert.h>
#include <time.h>
#include <openssl/sha.h>

clock_t start;
clock_t diff;


void printHexBytes(const char * prefix, const uint8_t *src, unsigned len, const char * suffix) {
  if (len == 0) {
    printf("%s <0 len char array> %s", prefix, suffix);
    return;
  }

  printf("%s", prefix);
  unsigned int i;
  for (i = 0; i < len-1; ++i) {
    printf("%02x",src[i] & 0xff);
  }
  printf("%02x%s",src[i] & 0xff, suffix);
}

void printBIGNUM(const char * prefix, const scalar_t bn, const char * suffix) {
  char *bn_str = BN_bn2dec(bn);
  printf("%s%s%s", prefix, bn_str, suffix);
  free(bn_str);
}

void time_sampling_scalars(uint64_t reps, const scalar_t range, int coprime)
{
  scalar_t alpha;

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    alpha = scalar_new();
    sample_in_range(alpha, range, coprime);
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

void test_paillier_operations(const paillier_private_key_t *priv) 
{
  printf("# test_paillier_operations\n");

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t plaintext = scalar_new();
  scalar_t randomness = scalar_new();
  scalar_t ciphertext = scalar_new();
  scalar_t decrypted = scalar_new();

  paillier_public_key_t *pub = paillier_encryption_copy_public(priv);
  
  sample_in_range(plaintext, pub->N , 0);
  printBIGNUM("plaintext = ", plaintext, "\n");

  paillier_encryption_sample(pub, randomness);
  printBIGNUM("randomness = ", (randomness), "\n");

  paillier_encryption_encrypt(pub, plaintext, randomness, ciphertext);
  printBIGNUM("ciphertext = ", (ciphertext), "\n");

  paillier_encryption_decrypt(priv, ciphertext, decrypted);
  printBIGNUM("decrypted = ", (decrypted), "\n");

  assert(BN_cmp(plaintext, decrypted) == 0);

  paillier_encryption_homomorphic(pub, ciphertext, plaintext, ciphertext, ciphertext);
  printBIGNUM("ciphertext = ", (ciphertext), "\n");

  paillier_encryption_decrypt(priv, ciphertext, decrypted);
  printBIGNUM("decrypted = ", (decrypted), "\n");

  BN_mod_mul(randomness, plaintext, plaintext, pub->N, bn_ctx);
  BN_mod_add(randomness, randomness, plaintext, pub->N, bn_ctx);
  printBIGNUM("expected  = ", (randomness), "\n");

  assert(BN_cmp(randomness, decrypted) == 0);

  paillier_encryption_free_keys(NULL, pub);
  scalar_free(plaintext);
  scalar_free(randomness);
  scalar_free(ciphertext);
  scalar_free(decrypted);
  BN_CTX_free(bn_ctx);
}

void time_paillier_encrypt(uint64_t reps, paillier_public_key_t *pub, unsigned long start_plain, unsigned long start_rand)
{ 
  printf("# Paillier Encryption\n");

  scalar_t plaintext = scalar_new();
  scalar_t ciphertext = scalar_new();
  scalar_t randomness = scalar_new();

  if (start_plain) BN_set_word(plaintext, start_plain);
  else sample_in_range(plaintext, pub->N, 0);
  if (start_rand) BN_set_word(randomness, start_rand);
  else sample_in_range(randomness, pub->N, 0);

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

void test_ring_pedersen(const scalar_t p, const scalar_t q) 
{
  printf("# test_ring_pedersen\n");

  ring_pedersen_private_t *rped_priv = ring_pedersen_generate_param(p, q);
  ring_pedersen_public_t *rped_pub = ring_pedersen_copy_public(rped_priv);

  printBIGNUM("N = ", (rped_pub->N), "\n");
  printBIGNUM("s = ", (rped_pub->s), "\n");
  printBIGNUM("t = ", (rped_pub->t), "\n");
  printBIGNUM("ped_lambda = ", (rped_priv->lambda), "\n");
  printBIGNUM("phi_N = ", (rped_priv->phi_N), "\n");

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  scalar_t s_exp = scalar_new();
  scalar_t t_exp = scalar_new();
  scalar_t rped_com = scalar_new();
  
  sample_in_range(s_exp, rped_pub->N, 0);
  printBIGNUM("s_exp = ", (s_exp), "\n");

  sample_in_range(t_exp, rped_pub->N, 0);
  printBIGNUM("t_exp = ", (t_exp), "\n");

  ring_pedersen_commit(rped_pub, s_exp, t_exp, rped_com);
  printBIGNUM("rped_com = ", (rped_com), "\n");

  ring_pedersen_free_param(rped_priv, rped_pub);
  scalar_free(s_exp);
  scalar_free(t_exp);
  scalar_free(rped_com);
  BN_CTX_free(bn_ctx);
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

  paillier_encryption_free_keys(priv, NULL);
}