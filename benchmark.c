#include "nikmak_ecdsa_mpc_poc.h"
#include <assert.h>
#include <time.h>

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

void time_sampling_scalars(uint64_t reps, const scalar_t range)
{
  scalar_t alpha;

  start = clock();

  for (uint64_t i = 0; i < reps; ++i)
  {
    alpha = scalar_new(ctx);
    sample_in_range(range, alpha);
    //printf("alpha: %s\n", BN_bn2dec(alphas[i]));
    scalar_free(alpha);
  }

  diff = clock() - start;
  printf("sampling scalars\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
}

void time_computing_group_pedersen(uint64_t reps)
{
  scalar_t alpha = scalar_new(ctx);
  scalar_t beta = scalar_new(ctx);

  sample_in_range((const scalar_t) EC_GROUP_get0_order(ctx->ec), alpha);
  sample_in_range((const scalar_t) EC_GROUP_get0_order(ctx->ec), beta);

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
}

void time_paillier_generate_keys(uint64_t reps)
{
  paillier_public_key_t pub;
  paillier_private_key_t priv;

  start = clock();  

  for (uint64_t i = 0; i < reps; ++i)
  {
    paillier_encryption_generate_new_keys(ctx, &pub, &priv);
    paillier_encryption_free_keys(&pub, &priv);
  }

  diff = clock() - start;
  printf("generating paillier safe keys\n%lu repetitions, time: %lu msec, avg: %f msec\n", reps, diff * 1000/ CLOCKS_PER_SEC, ((double) diff * 1000/ CLOCKS_PER_SEC) / reps);
}

void time_mod_exp(uint64_t reps, paillier_private_key_t *priv)
{ 
  scalar_t base = scalar_new(ctx);
  sample_in_range(priv->pub.N, base);
  
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
  sample_in_range(priv->pub.N, base);

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
  printf("generating single paillier priv/pub key pair: %lu msec\n", diff * 1000/ CLOCKS_PER_SEC);

  uint8_t digest[FIAT_SHAMIR_DIGEST_BYTES];

  fiat_shamir_hash(ctx, NULL, 0, digest);
  printHexBytes_padded("digest: ", digest, FIAT_SHAMIR_DIGEST_BYTES, "\n");

  time_computing_group_pedersen(10000);
  //time_paillier_generate_keys(4);
  //time_mod_exp(2000, &priv);
  //time_mod_exp_mont(2000, &priv);

  paillier_encryption_free_keys(&pub, &priv);
  protocol_ctx_free(ctx); 
}