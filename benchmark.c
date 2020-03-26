#include "nikmak_ecdsa_mpc_poc.h"
#include <assert.h>
#include <time.h>
#include <openssl/sha.h>

protocol_ctx_t *ctx;
clock_t start;
clock_t diff;


void printHexBytes_padded(const char * prefix, const uint8_t *src, unsigned len, const char * suffix) {
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

void time_sampling_scalars(uint64_t reps, const scalar_t range, int coprime)
{
  scalar_t alpha;

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    alpha = scalar_new(ctx);
    sample_in_range(ctx, range, alpha, coprime);
    //printf("alpha: %s\n", BN_bn2dec(alphas[i]));
    scalar_free(alpha);
  }

  diff = clock() - start;
  printf("sampling scalars (coprime: %d)\n%lu repetitions, time: %lu msec, avg: %f msec\n", coprime, reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
}

void time_computing_group_pedersen(uint64_t reps)
{
  scalar_t alpha = scalar_new(ctx);
  scalar_t beta = scalar_new(ctx);

  sample_in_range(ctx, (const scalar_t) EC_GROUP_get0_order(ctx->ec), alpha, 0);
  sample_in_range(ctx, (const scalar_t) EC_GROUP_get0_order(ctx->ec), beta, 0);

  start = clock();

  group_el_t ped_com;
  for (uint64_t i = 0; i < reps; ++i)
  {
    ped_com = group_el_new(ctx);
    group_pedersen_commitment(ctx, alpha, beta, ped_com);
    group_el_free(ped_com);
  }

  diff = clock() - start;
  printf("computing Pedersen\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);

  scalar_free(alpha);
  scalar_free(beta);
}

void time_paillier_generate_keys(uint64_t reps)
{
  paillier_public_key_t pub;
  paillier_private_key_t priv;
  int priv_prime_bits = 0;

  start = clock();  

  for (uint64_t i = 0; i < reps; ++i)
  {
    paillier_encryption_generate_new_keys(ctx, &pub, &priv);
    priv_prime_bits = BN_num_bits(priv.p);
    paillier_encryption_free_keys(&pub, &priv);
  }

  diff = clock() - start;
  printf("generating paillier (%d-bits primes) safe keys\n%lu repetitions, time: %lu msec, avg: %f msec\n", priv_prime_bits, reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
}

void time_mod_mult(uint64_t reps, paillier_private_key_t *priv)
{ 
  scalar_t base = scalar_new(ctx);
  sample_in_range(ctx, priv->pub.N, base, 0);
  
  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    BN_mod_mul(base, base, base, priv->pub.N2, ctx->bn_ctx);
    //printf("%s\n", BN_bn2dec(base));
  }

  diff = clock() - start;
  printf("computing mod mult\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
}


void time_mod_mult_mont(uint64_t reps, paillier_private_key_t *priv)
{ 
  BN_MONT_CTX *mnt_ctx = BN_MONT_CTX_new();
  BN_MONT_CTX_set(mnt_ctx, priv->pub.N2, ctx->bn_ctx);

  scalar_t base = scalar_new(ctx);
  sample_in_range(ctx, priv->pub.N, base, 0);

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    BN_mod_exp_mont(base, base, base, priv->pub.N2, ctx->bn_ctx, mnt_ctx);
    //printf("%s\n", BN_bn2dec(base));
  }
  
  diff = clock() - start;
  printf("computing mod mult mont\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);

  BN_MONT_CTX_free(mnt_ctx);
}

void time_mod_exp(uint64_t reps, paillier_private_key_t *priv)
{ 
  scalar_t base = scalar_new(ctx);
  sample_in_range(ctx, priv->pub.N, base, 0);
  
  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    BN_mod_exp(base, base, priv->pub.N, priv->pub.N2, ctx->bn_ctx);
    //printf("%s\n", BN_bn2dec(base));
  }

  diff = clock() - start;
  printf("computing mod exp\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
}

void time_mod_exp_mont(uint64_t reps, paillier_private_key_t *priv)
{ 
  BN_MONT_CTX *mnt_ctx = BN_MONT_CTX_new();
  BN_MONT_CTX_set(mnt_ctx, priv->pub.N2, ctx->bn_ctx);

  scalar_t base = scalar_new(ctx);
  sample_in_range(ctx, priv->pub.N, base, 0);

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    BN_mod_exp_mont(base, base, priv->pub.N, priv->pub.N2, ctx->bn_ctx, mnt_ctx);
    //printf("%s\n", BN_bn2dec(base));
  }

  diff = clock() - start;
  printf("computing Montgomery mod exp\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);

  BN_MONT_CTX_free(mnt_ctx);
}

void time_paillier_encrypt(uint64_t reps, paillier_public_key_t *pub, unsigned long start_plain, unsigned long start_rand, int coprime_rand)
{ 
  scalar_t plaintext = scalar_new(ctx);
  scalar_t ciphertext = scalar_new(ctx);
  scalar_t randomness = scalar_new(ctx);

  if (start_plain) BN_set_word(plaintext, start_plain);
  else sample_in_range(ctx, pub->N, plaintext, coprime_rand);
  if (start_rand) BN_set_word(randomness, start_rand);
  else sample_in_range(ctx, pub->N, randomness, start_rand);

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    paillier_encryption_encrypt(ctx, pub, plaintext, randomness, ciphertext);
    BN_add_word(plaintext, 1);
    BN_add_word(randomness, 1);
    //printf("plain : %s\nrandom: %s\ncipher: %s\n", BN_bn2dec(plaintext), BN_bn2dec(randomness), BN_bn2dec(ciphertext));
  }

  diff = clock() - start;
  printf("Paillier Encryption\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
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

  printf("Sha512 Digest\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
}

void compute_exp(scalar_t base, scalar_t exp, scalar_t modulos)
{
  int reps = 1;

  printf("pow(%s, %s, %s)\n", BN_bn2dec(base), BN_bn2dec(exp), BN_bn2dec(modulos));

  scalar_t res = scalar_new(ctx);
  scalar_t temp = scalar_new(ctx);
  
  BN_set_word(res, 1);

  int bit_len_exp = BN_num_bits(exp);

  start = clock();

  for (int i = bit_len_exp-1; i >= 0; --i)
  {
    BN_mod_sqr(res, res, modulos, ctx->bn_ctx);

    //if (BN_is_bit_set(exp, i))
      BN_mod_mul(res, res, base, modulos, ctx->bn_ctx);
    //printf("%d %s\n", BN_is_bit_set(exp, i), BN_bn2dec(res));
  }

  diff = clock() - start;

  printf("%s\n", BN_bn2dec(res));

  printf("COMPUTE EXP\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);

  scalar_free(res);
  scalar_free(temp);
}


int main()
{
  ctx = protocol_ctx_new();
  start = clock();
  paillier_public_key_t pub;
  paillier_private_key_t priv;
  paillier_encryption_generate_new_keys(ctx, &pub, &priv);
  diff = clock() - start;

  printf("group G gen : %s\n", EC_POINT_point2hex(ctx->ec, EC_GROUP_get0_generator(ctx->ec), POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
  printf("group H gen : %s\n", EC_POINT_point2hex(ctx->ec, ctx->H, POINT_CONVERSION_COMPRESSED, ctx->bn_ctx));
  printf("paillier key\np: %s\nq: %s\nlambda: %s\nmu: %s\nN: %s\nN2: %s\n", BN_bn2dec(priv.p), BN_bn2dec(priv.q), BN_bn2dec(priv.lambda), BN_bn2dec(priv.mu), BN_bn2dec(pub.N), BN_bn2dec(pub.N2));
  printf("generating single paillier (%d-bits primes) priv/pub key pair: %lu msec\n", BN_num_bits(priv.p), diff * 1000/ CLOCKS_PER_SEC);

  uint8_t digest[FIAT_SHAMIR_DIGEST_BYTES];


  fiat_shamir_hash(ctx, NULL, 0, digest);
  printHexBytes_padded("digest: ", digest, FIAT_SHAMIR_DIGEST_BYTES, "\n");

  time_hashing(1000, digest, FIAT_SHAMIR_DIGEST_BYTES);
  time_computing_group_pedersen(100);
  time_sampling_scalars(100, pub.N, 0);
  time_sampling_scalars(100, pub.N, 1);
  time_computing_group_pedersen(1000);
  //time_paillier_generate_keys(1);
  time_mod_exp(1, &priv);
  //time_mod_exp_mont(1000, &priv);
  time_paillier_encrypt(100, &pub, 0, 0, 1);
  time_mod_mult(4096, &priv);
  //time_mod_mult_mont(1000, &priv);

  scalar_t base = scalar_new(ctx);
  scalar_t exp = scalar_new(ctx);
  scalar_t modulos = scalar_new(ctx);

  BN_set_word(base, 7);
  BN_set_word(exp, 5);
  BN_set_word(modulos, 11);

  compute_exp(base, pub.N, pub.N2);

  scalar_free(base);
  scalar_free(exp);
  scalar_free(modulos);

  paillier_encryption_free_keys(&pub, &priv);
  protocol_ctx_free(ctx); 
}