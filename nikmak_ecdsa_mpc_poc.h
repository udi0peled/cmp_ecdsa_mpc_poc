#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#ifndef __NIKMAK_ECDSA_MPC_POC_H__
#define __NIKMAK_ECDSA_MPC_POC_H__

#define GROUP_ID NID_secp256k1
#define GROUP_ORDER_BYTES 32
#define GROUP_COMPRESSED_POINT_BYTES 33
#define GROUP_UNCOMPRESSED_POINT_BYTES 65
#define FIAT_SHAMIR_DIGEST_BYTES 32
#define PAILLIER_FACTOR_BYTES (2 * GROUP_ORDER_BYTES)
#define PAILLIER_FACTOR_BITS  (8 * PAILLIER_FACTOR_BYTES)
#define STATISTICAL_SECURITY 80


typedef const EC_GROUP *ec_group_t;
typedef EC_POINT *gr_elem_t;
typedef BIGNUM *scalar_t;

/**
 *  Protocol Context
 */

struct protocol_ctx 
{
  const EC_GROUP *ec;
  BN_CTX *bn_ctx;

  //const BIGNUM *q;
  //const EC_POINT *G;
  gr_elem_t H;

  const char *sid;
};


/** 
 * General Auxiliary Information for ZKProofs
 */

typedef struct
{
  uint8_t *info;
  uint64_t info_len;
} zkp_aux_info_t;


/**
 *  Paillier Encryption
 */

typedef struct 
{
  scalar_t N;
  scalar_t N2;
} paillier_public_key_t;

typedef struct 
{
  paillier_public_key_t pub;

  scalar_t p;
  scalar_t q;
  scalar_t lambda;              // exponent in decryption
  scalar_t mu;                  // multiplicative factor in decryption
} paillier_private_key_t;


/** 
 * Ring Pedersen Parameters
 */

typedef struct
{
  scalar_t N;
  scalar_t s;
  scalar_t t;
} ring_pedersen_public_t;


typedef struct
{
  ring_pedersen_public_t pub;

  scalar_t lambda;
  scalar_t phi_N;
} ring_pedersen_private_t;


/**
 *  Paillier-Blum Modulus ZKProof
 */

typedef struct
{
  struct {
    const scalar_t N;
  } public;

  struct {
    const scalar_t p;
    const scalar_t q;
  } secret;

  struct {
    scalar_t w;
    scalar_t x[STATISTICAL_SECURITY];
    scalar_t z[STATISTICAL_SECURITY];
    uint8_t a[STATISTICAL_SECURITY];
    uint8_t b[STATISTICAL_SECURITY];
  } proof;
} zkp_paillier_blum_modulus_t;


/**
 *  Ring Pedersend Parameters ZKProof
 */

typedef struct
{
  struct
  {
    const scalar_t N;
    const scalar_t s;
    const scalar_t t;
  } public;

  struct {
    const scalar_t lambda;
  } secret;

  struct {
    scalar_t A[STATISTICAL_SECURITY];
    scalar_t z[STATISTICAL_SECURITY];
  } proof;
} zkp_ring_pedersen_param_t;


/** 
 * Schnoor ZKProof
 */ 

typedef struct
{
  struct { 
    const ec_group_t G;
    const gr_elem_t g; 
    const gr_elem_t X;
  } public;

  struct {
    scalar_t x;
  } secret;

  struct {
    gr_elem_t A;
    scalar_t z;
  } proof;
} zkp_schnorr_t;


/** 
 *  Paillier Encryption in Range ZKProof 
 */

typedef struct
{
  struct { 
    const scalar_t N_hat;
    const scalar_t s;
    const scalar_t t;
    const scalar_t N_0;
    const scalar_t K;
  } public;

  struct {
    scalar_t k;
    scalar_t rho;
  } secret;

  struct {
    scalar_t S;
    scalar_t A;
    scalar_t C;
    scalar_t z_1;
    scalar_t z_2;
    scalar_t z_3;
  } proof;
} zkp_encryption_in_range_t;


/** 
 *  Group Element vs Paillier Paillier Encryption in Range ZKProof 
 */

typedef struct
{
  struct { 
    const scalar_t N_hat;
    const scalar_t s;
    const scalar_t t;
    const ec_group_t G;
    const gr_elem_t g; 
    const scalar_t N_0;
    const scalar_t C;
    const gr_elem_t X;
  } public;

  struct {
    scalar_t x;
    scalar_t rho;
  } secret;

  struct {
    scalar_t S;
    scalar_t A;
    gr_elem_t Y;
    scalar_t D;
    scalar_t z_1;
    scalar_t z_2;
    scalar_t z_3;
    scalar_t w;
  } proof;
} zkp_group_vs_paillier_range_t;


/** 
 *  Paillier Affine Operation with Group Commitment in Range ZKProof 
 */

typedef struct
{
  struct { 
    const scalar_t N_hat;
    const scalar_t s;
    const scalar_t t;
    const ec_group_t G;
    const gr_elem_t g;
    const scalar_t N_0;
    const scalar_t N_1;
    const scalar_t C;
    const scalar_t D;
    const scalar_t Y;
    const gr_elem_t X;
  } public;


  struct {
    scalar_t x;
    scalar_t y;
    scalar_t rho;
    scalar_t rho_y;
  } secret;

  struct {
    scalar_t A;
    gr_elem_t B_x;
    scalar_t B_y;
    scalar_t E;
    scalar_t F;
    scalar_t z_1;
    scalar_t z_2;
    scalar_t z_3;
    scalar_t z_4;
    scalar_t w;
    scalar_t w_y;
  } proof;
} zkp_operation_group_commitment_range_t;


/** 
 *  Paillier Affine Operation with Paillier Commitment in Range ZKProof 
 */

typedef struct
{
  struct { 
    const scalar_t N_hat;
    const scalar_t s;
    const scalar_t t;
    const scalar_t N_0;
    const scalar_t N_1;
    const scalar_t C;
    const scalar_t D;
    const scalar_t Y;
    const scalar_t X;
  } public;

  struct {
    scalar_t x;
    scalar_t y;
    scalar_t rho;
    scalar_t rho_x;
    scalar_t rho_y;
  } secret;

  struct {
    scalar_t A;
    scalar_t B_x;
    scalar_t B_y;
    scalar_t E;
    scalar_t F;
    scalar_t z_1;
    scalar_t z_2;
    scalar_t z_3;
    scalar_t z_4;
    scalar_t w;
    scalar_t w_x;
    scalar_t w_y;
  } proof;
} zkp_operation_paillier_commitment_range_t;


// protocol_ctx_t *protocol_ctx_new ();
// void            protocol_ctx_free(protocol_ctx_t *ctx);

void fiat_shamir_hash(const uint8_t *data, const uint64_t data_len, uint8_t digest[FIAT_SHAMIR_DIGEST_BYTES]);

scalar_t scalar_new();
void scalar_free (scalar_t el);
void sample_in_range(scalar_t rnd, const scalar_t range_mod, int coprime);

ec_group_t  ec_group_get();
gr_elem_t   group_elem_new ();
void        group_elem_free(gr_elem_t el);
void        group_multiplication     (const gr_elem_t a, const gr_elem_t b, gr_elem_t c);
void        group_exponentiation     (const gr_elem_t a, const scalar_t exp, gr_elem_t c);

paillier_private_key_t *
      paillier_encryption_generate_key      ();
paillier_public_key_t *
      paillier_encryption_copy_public       (const paillier_private_key_t *priv);
void  paillier_encryption_free_keys         (paillier_private_key_t *priv, paillier_public_key_t *pub);
void  paillier_encryption_sample            (const paillier_public_key_t *pub, scalar_t rho);
void  paillier_encryption_encrypt           (const paillier_public_key_t *pub, const scalar_t plaintext, const scalar_t rho, scalar_t ciphertext);
void  paillier_encryption_decrypt           (const paillier_private_key_t *priv, const scalar_t ciphertext, scalar_t plaintext);
void  paillier_encryption_homomorphic       (const paillier_public_key_t *pub, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, scalar_t new_cipher);       // factor == NULL, assume 1. add_cipher == NULL, assume 0

ring_pedersen_private_t *
      ring_pedersen_generate_param  (const scalar_t p, const scalar_t q);       // Assumes p,q safe primes (no check)
ring_pedersen_public_t *
      ring_pedersen_copy_public     (const ring_pedersen_private_t *priv);
void  ring_pedersen_free_param      (ring_pedersen_private_t *priv, ring_pedersen_public_t *pub);
void  ring_pedersen_commit          (const ring_pedersen_public_t *rped_pub, const scalar_t s_exp, const scalar_t t_exp, scalar_t rped_commitment);

// Zero Knowledge Proofs

zkp_paillier_blum_modulus_t *
      zkp_paillier_blum_new    ();
void  zkp_paillier_blum_free   (zkp_paillier_blum_modulus_t *proof);
void  zkp_paillier_blum_prove  (zkp_paillier_blum_modulus_t *proof, const zkp_aux_info_t *aux);
int   zkp_paillier_blum_verify (zkp_paillier_blum_modulus_t *proof);

zkp_ring_pedersen_param_t *
      zkp_ring_pedersen_param_new    ();
void  zkp_ring_pedersen_param_free   (zkp_ring_pedersen_param_t *proof);
void  zkp_ring_pedersen_param_prove  (zkp_ring_pedersen_param_t *proof, const zkp_aux_info_t *aux, const zkp_ring_pedersen_param_t *secret);
int   zkp_ring_pedersen_param_verify (zkp_ring_pedersen_param_t *proof);

zkp_schnorr_t *
      zkp_schnorr_new     ();
void  zkp_schnorr_free    (zkp_schnorr_t *proof);
void  zkp_schnorr_commit  (zkp_schnorr_t *proof, scalar_t alpha);
void  zkp_schnorr_prove   (zkp_schnorr_t *proof, const zkp_aux_info_t *aux, const scalar_t x, const scalar_t alpha);      // alpha == NULL, sample random
int   zkp_schnorr_verify  (zkp_schnorr_t *proof);

zkp_encryption_in_range_t *
      zkp_encryption_in_range_new    ();
void  zkp_encryption_in_range_free   (zkp_encryption_in_range_t *proof);
void  zkp_encryption_in_range_prove  (zkp_encryption_in_range_t *proof, const zkp_aux_info_t *aux);
int   zkp_encryption_in_range_verify (zkp_encryption_in_range_t *proof);


zkp_group_vs_paillier_range_t *
      zkp_group_vs_paillier_range_new    ();
void  zkp_group_vs_paillier_range_free   (zkp_group_vs_paillier_range_t *proof);
void  zkp_group_vs_paillier_range_prove  (zkp_group_vs_paillier_range_t *proof, const zkp_aux_info_t *aux);
int   zkp_group_vs_paillier_range_verify (zkp_group_vs_paillier_range_t *proof);


zkp_operation_group_commitment_range_t *
      zkp_operation_group_commitment_range_new    ();
void  zkp_operation_group_commitment_range_prove  (zkp_operation_group_commitment_range_t *proof, const zkp_aux_info_t *aux);
int   zkp_operation_group_commitment_range_verify (zkp_operation_group_commitment_range_t *proof);
void  zkp_operation_group_commitment_range_free   (zkp_operation_group_commitment_range_t *proof);

zkp_operation_paillier_commitment_range_t*
      zkp_operation_paillier_commitment_range_new    ();
void  zkp_operation_paillier_commitment_range_free   (zkp_operation_paillier_commitment_range_t *proof);
void  zkp_operation_paillier_commitment_range_prove  (zkp_operation_paillier_commitment_range_t *proof, const zkp_aux_info_t *aux);
int   zkp_operation_paillier_commitment_range_verify (zkp_operation_paillier_commitment_range_t *proof);

#endif