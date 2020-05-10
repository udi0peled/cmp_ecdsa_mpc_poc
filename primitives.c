#include "primitives.h"
#include "common.h"

#include <string.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/objects.h>

// protocol_ctx_t *protocol_ctx_new()
// {
//   protocol_ctx_t *ctx = malloc(sizeof(protocol_ctx_t));
//   ctx->ec = EC_GROUP_new_by_curve_name(GROUP_ID);

//   ctx->bn_ctx = BN_CTX_new();
  
//   // Set session id (fixed throughout benchmarking)
//   ctx->sid = "Fireblocks - Benchmarking NikMak MPC";

//   return ctx;
// }


// void protocol_ctx_free(protocol_ctx_t *ctx)
// {
//   EC_POINT_free(ctx->H);
//   BN_CTX_free(ctx->bn_ctx);
//   free(ctx);
// }

/** 
 *  Scalar and Group Elements Basics
 */

scalar_t scalar_new() { return BN_secure_new(); }
void scalar_free(scalar_t num) { BN_clear_free(num); }

void scalar_add (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BN_mod_add(result, first, second, modulus, bn_ctx);
  BN_CTX_free(bn_ctx);
}

void scalar_mul (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BN_mod_mul(result, first, second, modulus, bn_ctx);
  BN_CTX_free(bn_ctx);
}

void scalar_inv (scalar_t result, const scalar_t num, const scalar_t modulus)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BN_mod_inverse(result, num, modulus, bn_ctx);
  BN_CTX_free(bn_ctx);
}

void scalar_to_bytes(uint8_t *bytes, uint64_t byte_len, scalar_t num)
{
  if (byte_len >= (uint64_t) BN_num_bytes(num))
    BN_bn2binpad(num, bytes, byte_len);
}

ec_group_t  ec_group_new () { return EC_GROUP_new_by_curve_name(GROUP_ID); }
void        ec_group_free (ec_group_t ec) { EC_GROUP_free(ec); }
scalar_t    ec_group_order      (ec_group_t ec) { return (scalar_t) EC_GROUP_get0_order(ec); }

gr_elem_t   group_elem_new (const ec_group_t ec) { return EC_POINT_new(ec); }
void        group_elem_free (gr_elem_t el) { EC_POINT_clear_free(el); }

/**
 *  Computes g^{g_exp}*(\Pi_i bases[i]^exps[i]).
 *  num_bases can be 0, and bases == exps NULL.
 *  if num_bases > 0, and exp == NULL, set ones (bases must of length num_bases).
 */
void group_operation (gr_elem_t result, const scalar_t g_exp, const gr_elem_t *bases, const scalar_t *exps, uint64_t num_bases, const ec_group_t ec)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  int free_use_exps = 0;
  scalar_t *use_exps = (scalar_t *) exps;
  // If exps is null, set all to 1
  if (!use_exps)
  {
    use_exps = calloc(num_bases, sizeof(scalar_t));
    free_use_exps = 1;
    for (uint64_t i = 0; i < num_bases; ++i) use_exps[i] = (scalar_t) BN_value_one();
  }
  EC_POINTs_mul(ec, result, g_exp, num_bases, (const EC_POINT **) bases, (const BIGNUM **) use_exps, bn_ctx);

  if (free_use_exps) free(use_exps);
  BN_CTX_free(bn_ctx);
}

void group_elem_to_bytes (uint8_t *bytes, uint64_t byte_len, gr_elem_t el, ec_group_t ec)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  EC_POINT_point2oct(ec, el, POINT_CONVERSION_COMPRESSED, bytes, byte_len, bn_ctx);
  BN_CTX_free(bn_ctx);
}

void scalar_sample_in_range(scalar_t rnd, const scalar_t range_mod, int coprime)
{
  BN_rand_range(rnd, range_mod);

  if (coprime)
  { 
    BN_CTX * bn_ctx = BN_CTX_secure_new();
    BIGNUM *gcd = scalar_new();
    BN_gcd(gcd, range_mod, rnd, bn_ctx);
    
    while (!BN_is_one(gcd))
    {
      BN_rand_range(rnd, range_mod);
      BN_gcd(gcd, range_mod, rnd, bn_ctx);
    }
    
    scalar_free(gcd);
    BN_CTX_free(bn_ctx);
  }
}

void sample_safe_prime(unsigned int bits, scalar_t prime)
{
  BN_generate_prime_ex(prime, bits, 1, NULL, NULL, NULL);
}


/**
 *  Fiat-Shamir / Random Oracle
 */

#define FS_HALF 32      // Half of SHA512 64 bytes digest

/** 
 *  Denote hash digest as 2 equal length parts (LH, RH) - together (LH,RH,data) is curr_digest.
 *  Iteratively Hash (RH,data) to get next Hash digest (LH,RH).
 *  Concatenate all LH of iterations to digest, until getting required digest_len bytes.
 *  Initialize first RH to given state, and final RH returned at state - which allows for future calls on same data, getting new digests
 */

static void fiat_shamir_bytes_from_state(uint8_t *digest, uint64_t digest_len, const uint8_t *data, uint64_t data_len, uint8_t state[FS_HALF])
{ 
  // Initialize RH to state, so the first hash will be on (state, data).
  uint8_t *curr_digest = malloc(2*FS_HALF + data_len);
  memcpy(curr_digest + FS_HALF, state, FS_HALF);
  memcpy(curr_digest + 2*FS_HALF, data, data_len);

  uint64_t add_curr_digest_bytes;

  while (digest_len > 0)
  {  
    // hash previous (RH,data) to get new (LH, RH)
    SHA512(curr_digest + FS_HALF, FS_HALF + data_len, curr_digest);

    add_curr_digest_bytes = (digest_len < FS_HALF ? digest_len : FS_HALF);
    
    // collect current LH to final digest
    memcpy(digest, curr_digest, add_curr_digest_bytes);
    
    digest += add_curr_digest_bytes;
    digest_len -= add_curr_digest_bytes;
  }

  // Keep last RH as state for future calls on same data
  memcpy(state, curr_digest + FS_HALF, FS_HALF);
  memset(curr_digest, 0, 2*FS_HALF + data_len);
  free(curr_digest);
}

void fiat_shamir_bytes(uint8_t *digest, uint64_t digest_len, const uint8_t *data, uint64_t data_len)
{
  uint8_t initial_zero_state[FS_HALF] = {0};
  fiat_shamir_bytes_from_state(digest, digest_len, data, data_len, initial_zero_state);
  memset(initial_zero_state, 0, FS_HALF);
}

/** 
 *  Get num_res scalars from fiat-shamir on data.
 *  Rejection sampling each scalar until fits in given range.
 */

void fiat_shamir_scalars_in_range(scalar_t *results, uint64_t num_res, const scalar_t range, const uint8_t *data, uint64_t data_len)
{
  uint64_t num_bits = BN_num_bits(range);
  uint64_t num_bytes = BN_num_bytes(range);

  uint8_t fs_state[FS_HALF] = {0};
  uint8_t *result_bytes = calloc(num_bytes, 1);

  for (uint64_t i_res = 0; i_res < num_res; ++i_res)
  {
    BN_copy(results[i_res], range);
    
    while (BN_cmp(results[i_res], range) != -1)
    {
      fiat_shamir_bytes_from_state(result_bytes, num_bytes, data, data_len, fs_state);
      printHexBytes("result_bytes = ", result_bytes, num_bytes, "\n");
      BN_bin2bn(result_bytes, num_bytes, results[i_res]);
      printBIGNUM("result (before trunc)= ", results[i_res], "\n");
      BN_mask_bits(results[i_res], num_bits);
      printBIGNUM("result (after trunc)= ", results[i_res], "\n");
    }
    printf("\n");
  }

  memset(fs_state, 0, FS_HALF);
  free(result_bytes);
}


/**
 *  Paillier Encryption Operations
 */

paillier_private_key_t *paillier_encryption_generate_key ()
{
  paillier_private_key_t *priv = malloc(sizeof(* priv));

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  priv->p       = scalar_new();
  priv->q       = scalar_new();
  priv->mu      = scalar_new();
  priv->lambda  = scalar_new();
  priv->pub.N   = scalar_new();
  priv->pub.N2  = scalar_new();

  sample_safe_prime(8*PAILLIER_FACTOR_BYTES, priv->p);
  sample_safe_prime(8*PAILLIER_FACTOR_BYTES, priv->q);

  BN_mul(priv->pub.N, priv->p, priv->q, bn_ctx);
  BN_sqr(priv->pub.N2, priv->pub.N, bn_ctx);

  BN_sub(priv->lambda, priv->pub.N, priv->p);
  BN_sub(priv->lambda, priv->lambda, priv->q);
  BN_add_word(priv->lambda, 1);

  BN_mod_inverse(priv->mu, priv->lambda, priv->pub.N, bn_ctx);
  
  BN_CTX_free(bn_ctx);

  return priv;
}

paillier_public_key_t *paillier_encryption_copy_public (const paillier_private_key_t *priv)
{
  paillier_public_key_t *pub = malloc(sizeof(*pub));

  pub->N = BN_dup(priv->pub.N);
  pub->N2 = BN_dup(priv->pub.N2);

  return pub;
}

void paillier_encryption_free_keys (paillier_private_key_t *priv, paillier_public_key_t *pub)
{
  if (priv) 
  {
    scalar_free(priv->p);
    scalar_free(priv->q);
    scalar_free(priv->lambda);
    scalar_free(priv->mu);
    scalar_free(priv->pub.N);
    scalar_free(priv->pub.N2);

    free(priv);
  }

  if (pub)
  {
    scalar_free(pub->N);
    scalar_free(pub->N2);

    free(pub);
  }
}


void paillier_encryption_sample(const paillier_public_key_t *pub, scalar_t rho)
{
  scalar_sample_in_range(rho, pub->N, 1);
}


void paillier_encryption_encrypt(const paillier_public_key_t *pub, const scalar_t plaintext, const scalar_t rho, scalar_t ciphertext)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new(); 
  BIGNUM *first_factor = scalar_new();
  BIGNUM *res_ciphertext = scalar_new();
  
  BN_mod_mul(first_factor, pub->N, plaintext, pub->N2, bn_ctx);
  BN_add_word(first_factor, 1);
  BN_mod_exp(res_ciphertext, rho, pub->N, pub->N2, bn_ctx);
  BN_mod_mul(res_ciphertext, first_factor, res_ciphertext, pub->N2, bn_ctx);

  BN_copy(ciphertext, res_ciphertext);
  scalar_free(res_ciphertext);
  scalar_free(first_factor);
  BN_CTX_free(bn_ctx);
}


void paillier_encryption_decrypt(const paillier_private_key_t *priv, const scalar_t ciphertext, scalar_t plaintext)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BIGNUM *res_plaintext = scalar_new();

  BN_mod_exp(res_plaintext, ciphertext, priv->lambda, priv->pub.N2, bn_ctx);
  BN_sub_word(res_plaintext, 1);
  BN_div(res_plaintext, NULL, res_plaintext, priv->pub.N, bn_ctx);
  BN_mod_mul(res_plaintext, res_plaintext, priv->mu, priv->pub.N, bn_ctx);

  BN_copy(plaintext, res_plaintext);
  scalar_free(res_plaintext);
  BN_CTX_free(bn_ctx);
}

void paillier_encryption_homomorphic(const paillier_public_key_t *pub, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, scalar_t new_cipher)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BIGNUM *res_new_cipher = BN_dup(ciphertext);

  if (factor) {
    BN_mod_exp(res_new_cipher, res_new_cipher, factor, pub->N2, bn_ctx);
  }
  
  if (add_cipher){
    BN_mod_mul(res_new_cipher, res_new_cipher, add_cipher, pub->N2, bn_ctx);
  }

  BN_copy(new_cipher, res_new_cipher);
  scalar_free(res_new_cipher);
  BN_CTX_free(bn_ctx);
}


/** 
 * Ring Pedersen Parameters
 */

ring_pedersen_private_t *ring_pedersen_generate_param  (const scalar_t p, const scalar_t q)
{
  ring_pedersen_private_t *priv = malloc(sizeof(*priv));

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  priv->phi_N = scalar_new();
  priv->lambda = scalar_new();
  priv->pub.N = scalar_new();
  priv->pub.s = scalar_new();
  priv->pub.t = scalar_new();

  BN_mul(priv->pub.N, p, q, bn_ctx);

  BN_sub(priv->phi_N, priv->pub.N, p);
  BN_sub(priv->phi_N, priv->phi_N, q);
  BN_add_word(priv->phi_N, 1);

  scalar_sample_in_range(priv->lambda, priv->phi_N, 0);

  BIGNUM *r = scalar_new();
  scalar_sample_in_range(r, priv->pub.N, 1);
  BN_mod_mul(priv->pub.t, r, r, priv->pub.N, bn_ctx);
  BN_mod_exp(priv->pub.s, priv->pub.t, priv->lambda, priv->pub.N, bn_ctx);

  scalar_free(r);
  BN_CTX_free(bn_ctx);

  return priv;
}

ring_pedersen_public_t *ring_pedersen_copy_public(const ring_pedersen_private_t *priv)
{
  ring_pedersen_public_t *pub = malloc(sizeof(*pub));

  pub->N = BN_dup(priv->pub.N);
  pub->t = BN_dup(priv->pub.t);
  pub->s = BN_dup(priv->pub.s);

  return pub;
}

void  ring_pedersen_free_param(ring_pedersen_private_t *priv, ring_pedersen_public_t *pub)
{
  if (priv)
  {
    scalar_free(priv->lambda);
    scalar_free(priv->phi_N);
    scalar_free(priv->pub.N);
    scalar_free(priv->pub.s);
    scalar_free(priv->pub.t);

    free(priv);
  }

  if (pub)
  {
    scalar_free(pub->N);
    scalar_free(pub->s);
    scalar_free(pub->t);

    free(pub);
  }
}

void  ring_pedersen_commit(const ring_pedersen_public_t *rped_pub, const scalar_t s_exp, const scalar_t t_exp, scalar_t rped_commitment)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t first_factor = scalar_new();
  scalar_t res_rped_commitment = scalar_new();

  BN_mod_exp(first_factor, rped_pub->s, s_exp, rped_pub->N, bn_ctx);
  BN_mod_exp(res_rped_commitment, rped_pub->t, t_exp, rped_pub->N, bn_ctx);
  BN_mod_mul(res_rped_commitment, first_factor, res_rped_commitment, rped_pub->N, bn_ctx);

  BN_copy(rped_commitment, res_rped_commitment);
  scalar_free(res_rped_commitment);
  scalar_free(first_factor);
  BN_CTX_free(bn_ctx);
}


/** 
 * Schnorr ZKProof
 */

zkp_schnorr_t *zkp_schnorr_new()
{
  zkp_schnorr_t *zkp = malloc(sizeof(*zkp));
  
  zkp->proof.A = group_elem_new(zkp->public.G);
  zkp->proof.z = scalar_new();

  return zkp;
}

void zkp_schnorr_free (zkp_schnorr_t *zkp)
{
  group_elem_free(zkp->proof.A);
  scalar_free(zkp->proof.z);
  free(zkp);
}

void zkp_schnorr_commit (zkp_schnorr_t *zkp, scalar_t alpha)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_sample_in_range(alpha, ec_group_order(zkp->public.G), 0);
  EC_POINT_mul(zkp->public.G, zkp->proof.A, NULL, zkp->public.g, alpha, bn_ctx);

  BN_CTX_free(bn_ctx);
}

void zkp_schnoor_challenge(scalar_t e, const zkp_schnorr_t *zkp, const zkp_aux_info_t *aux)
{
  uint64_t fs_data_len = aux->info_len + 3*GROUP_COMPRESSED_POINT_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);

  memcpy(fs_data, aux->info, aux->info_len);
  group_elem_to_bytes(fs_data + aux->info_len, GROUP_COMPRESSED_POINT_BYTES, zkp->public.g, zkp->public.G);
  group_elem_to_bytes(fs_data + aux->info_len + GROUP_COMPRESSED_POINT_BYTES, GROUP_COMPRESSED_POINT_BYTES, zkp->public.X, zkp->public.G);
  group_elem_to_bytes(fs_data + aux->info_len + 2*GROUP_COMPRESSED_POINT_BYTES, GROUP_COMPRESSED_POINT_BYTES, zkp->proof.A, zkp->public.G);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(zkp->public.G), fs_data, fs_data_len);

  free(fs_data);
}

void zkp_schnorr_prove (zkp_schnorr_t *zkp, const zkp_aux_info_t *aux, const scalar_t alpha)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  EC_POINT_mul(zkp->public.G, zkp->proof.A, NULL, zkp->public.g, alpha, bn_ctx);

  scalar_t e = scalar_new();
  zkp_schnoor_challenge(e, zkp, aux);

  BN_mod_mul(zkp->proof.z, e, zkp->secret.x, ec_group_order(zkp->public.G), bn_ctx);
  BN_mod_add(zkp->proof.z, zkp->proof.z, alpha, ec_group_order(zkp->public.G), bn_ctx);

  BN_CTX_free(bn_ctx);
}

int zkp_schnorr_verify (zkp_schnorr_t *zkp, const zkp_aux_info_t *aux)
{

}