#ifndef __NIKMAK_ECDSA_MPC_POC_H__
#define __NIKMAK_ECDSA_MPC_POC_H__

#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define GROUP_ID NID_secp256k1
#define GROUP_ORDER_BYTES 32
#define GROUP_COMPRESSED_POINT_BYTES 33
#define GROUP_UNCOMPRESSED_POINT_BYTES 65
#define FIAT_SHAMIR_DIGEST_BYTES 32

typedef struct protocol_ctx protocol_ctx_t;

typedef EC_POINT *group_el_t;
typedef BIGNUM *scalar_t;

// group pedersen structures

typedef struct
{
  struct {
    scalar_t kappa;
    scalar_t rho;
  } secrets;

  struct {
    group_el_t K;
  } public;

  struct {
    scalar_t alpha;
    scalar_t beta;
  } randomness;

  struct {
    group_el_t A;
  } anchor;

  struct {
    scalar_t z1;
    scalar_t z2;
  } proof;

} group_pedersen_pok_t;

// discrete log group pedersen structures

typedef struct
{
  struct {
    scalar_t kappa;
    scalar_t rho;
  } secrets;

  struct {
    group_el_t K;
    group_el_t Delta;
    group_el_t Gamma;
  } public;

  struct {
    scalar_t alpha;
    scalar_t beta;  
  } randomness; 

  struct {
    group_el_t A;
    group_el_t C;
  } anchor;

  struct {
    scalar_t z1;
    scalar_t z2;
  } proof;

} dlog_group_pedersen_pok_t;

// paillier encryption and ring pedersen structures

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
  scalar_t lambda;  // exponent in decryption
  scalar_t mu;   // multiplicative factor in decryption
} paillier_private_key_t;

typedef struct
{
  scalar_t N;
  scalar_t s;
  scalar_t t;
} ring_pedersen_parameters_t;

// paillier range proof structures


typedef struct
{
  struct {
    scalar_t kappa;
    scalar_t rho;
    scalar_t r0;
  } secrets;

  struct {
    paillier_public_key_t *pub;
    ring_pedersen_parameters_t *ring;
    group_el_t K;
    scalar_t ciphertext;
    scalar_t range_bound;
    scalar_t bound_slack;
  } public;

  struct {
    scalar_t alpha;
    scalar_t mu;
    scalar_t r;
    scalar_t beta;
    scalar_t gamma;
  } randomness;

  struct {
    group_el_t S;
    group_el_t A;
    group_el_t B;
    group_el_t C;
  } anchor;

  struct {
    scalar_t z1;
    scalar_t z2;
    scalar_t z3;
    scalar_t w;
  } proof;
} paillier_range_pok_t;

// paillier affine range proof structures

typedef struct
{
  struct {
    scalar_t kappa;
    scalar_t rho;
    scalar_t r0;
  } secrets;

  struct {
    paillier_public_key_t *pub;
    ring_pedersen_parameters_t *ring;
    
    group_el_t X;
    scalar_t ciphertext1;
    scalar_t ciphertext2;

    scalar_t range_bound;
    scalar_t bound_slack;
  } public;

  struct {
    scalar_t alpha;
    scalar_t beta;
    scalar_t r;
    scalar_t gamma;
    scalar_t nu;
    scalar_t delta;
    scalar_t mu;
  } randomness;

  struct {
    group_el_t S;
    group_el_t T;
    group_el_t A;
    group_el_t B;
    group_el_t C;
    group_el_t D;
  } anchor;

  struct {
    scalar_t z1;
    scalar_t z2;
    scalar_t z3;
    scalar_t z4;
    scalar_t w;
  } proof;

} paillier_affine_range_pok_t;

struct protocol_ctx 
{
  const EC_GROUP *ec;
  BN_CTX *bn_ctx;

  //const BIGNUM *q;
  //const EC_POINT *G;
  group_el_t H;

  const char *sid;

};

typedef enum {
  SIGMA_PROTO_INIT            = 0,
  SIGMA_PROTO_FREE            = 1,
  SIGMA_PROTO_SAMPLE_COPRIME  = 2,
  SIGMA_PROTO_SAMPLE          = 3,
  SIGMA_PROTO_ANCHOR          = 4,
  SIGMA_PROTO_CHALLENGE       = 5,
  SIGMA_PROTO_PROVE           = 6,
  SIGMA_PROTO_VERIFY          = 7,
} sigma_proto_phase;

protocol_ctx_t *protocol_ctx_new ();
void            protocol_ctx_free(protocol_ctx_t *ctx);

scalar_t scalar_new(const protocol_ctx_t *ctx);
void scalar_free (scalar_t el);

group_el_t group_el_new (const protocol_ctx_t *ctx);
void group_el_free(group_el_t el);

void sample_in_range(const protocol_ctx_t *ctx, const scalar_t range_mod, scalar_t rnd, int coprime);

void fiat_shamir_hash(const protocol_ctx_t *ctx, const uint8_t *data, const uint64_t data_len, uint8_t digest[FIAT_SHAMIR_DIGEST_BYTES]);

void group_multiplication     (const protocol_ctx_t *ctx, const group_el_t a, const group_el_t b, group_el_t c);
void group_exponentiation     (const protocol_ctx_t *ctx, const group_el_t a, const scalar_t exp, group_el_t c);
void group_pedersen_commitment(const protocol_ctx_t *ctx, const scalar_t alpha, const scalar_t beta, group_el_t ped_com);

void paillier_encryption_generate_new_keys  (const protocol_ctx_t *ctx, paillier_public_key_t *pub, paillier_private_key_t *priv);
void paillier_encryption_free_keys          (paillier_public_key_t *pub, paillier_private_key_t *priv);
void paillier_encryption_sample             (const protocol_ctx_t *ctx, const paillier_public_key_t *pub, scalar_t rho, int sample_coprime);
void paillier_encryption_encrypt            (const protocol_ctx_t *ctx, const paillier_public_key_t *pub, const scalar_t plaintext, const scalar_t rho, scalar_t ciphertext);
void paillier_encryption_decrypt            (const protocol_ctx_t *ctx, const paillier_private_key_t *priv, const scalar_t ciphertext, scalar_t plaintext);
void paillier_encryption_homomorphic        (const protocol_ctx_t *ctx, const paillier_public_key_t *pub, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, scalar_t new_cipher);

void ring_pedersen_params_from_paillier (const protocol_ctx_t *ctx, const paillier_public_key_t *pub, ring_pedersen_parameters_t *params);
void ring_pedersen_commitment           (const protocol_ctx_t *ctx, const ring_pedersen_parameters_t *ring_params, const scalar_t alpha, const scalar_t beta, scalar_t ring_ped_com);

void group_pedersen_pok         (const protocol_ctx_t *ctx, const sigma_proto_phase action, group_pedersen_pok_t *proto_data);
void dlog_group_pedersen_pok    (const protocol_ctx_t *ctx, const sigma_proto_phase action, dlog_group_pedersen_pok_t *proto_data);
void paillier_range_pok         (const protocol_ctx_t *ctx, const sigma_proto_phase action, paillier_range_pok_t *proto_data);
void paillier_affine_range_pok  (const protocol_ctx_t *ctx, const sigma_proto_phase action, paillier_affine_range_pok_t *proto_data);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __SECP256K1_ALGEBRA_H__
