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

// general 2 exponenets

typedef scalar_t pedersen_exponents_t[2];

// group pedersen structures

typedef struct
{
  group_el_t K;
} group_pedersen_pok_public_t;

typedef struct 
{
  group_el_t A;
} group_pedersen_pok_anchor_t;

typedef struct 
{
  group_pedersen_pok_anchor_t anchor;
  scalar_t z1;
  scalar_t z2;
} group_pedersen_pok_proof_t;

// discrete log group pedersen structures

typedef struct
{
  group_el_t K;
  group_el_t Delta;
  group_el_t Gamma;
} dlog_group_pedersen_pok_public_t;

typedef struct 
{
  group_el_t A;
  group_el_t C;
} dlog_group_pedersen_pok_anchor_t;

typedef struct 
{
  dlog_group_pedersen_pok_anchor_t anchor;
  scalar_t z1;
  scalar_t z2;
} dlog_group_pedersen_pok_proof_t;

// paillier encryption and ring pedersen structures

typedef struct 
{
  scalar_t N;
  scalar_t N2;
} paillier_public_key_t;

typedef struct 
{
  paillier_public_key_t *pub;
  scalar_t p;
  scalar_t q;
  scalar_t lcm;  // exponent in decryption
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
  paillier_public_key_t *pub;
  ring_pedersen_parameters_t *ring;

  group_el_t K;
  scalar_t ciphertext;

  scalar_t range_bound;
  scalar_t bound_slack;
} paillier_range_pok_public_t;

typedef struct
{
  scalar_t alpha;
  scalar_t mu;
  scalar_t r;
  scalar_t beta;
  scalar_t gamma;
} paillier_range_pok_randomness_t;

typedef struct
{
  pedersen_exponents_t exp;
  scalar_t r0;
} paillier_range_pok_secrets_t;

typedef struct
{
  group_el_t S;
  group_el_t A;
  group_el_t B;
  group_el_t C;
} paillier_range_pok_anchor_t;

typedef struct
{
  paillier_range_pok_anchor_t anchor;
  scalar_t z1;
  scalar_t z2;
  scalar_t z3;
  scalar_t w;
} paillier_range_pok_proof_t;

// paillier affine range proof structures

typedef struct
{
  paillier_public_key_t *pub;
  ring_pedersen_parameters_t *ring;
  
  group_el_t X;
  scalar_t ciphertext1;
  scalar_t ciphertext2;

  scalar_t range_bound;
  scalar_t bound_slack;
} paillier_affine_range_pok_public_t;

typedef struct
{
  scalar_t alpha;
  scalar_t beta;
  scalar_t r;
  scalar_t gamma;
  scalar_t nu;
  scalar_t delta;
  scalar_t mu;
} paillier_affine_range_pok_randomness_t;

typedef struct
{
  pedersen_exponents_t exp;
  scalar_t r0;
} paillier_affine_range_pok_secrets_t;

typedef struct
{
  group_el_t S;
  group_el_t T;
  group_el_t A;
  group_el_t B;
  group_el_t C;
  group_el_t D;
} paillier_affine_range_pok_anchor_t;

typedef struct
{
  paillier_affine_range_pok_anchor_t anchor;
  scalar_t z1;
  scalar_t z2;
  scalar_t z3;
  scalar_t z4;
  scalar_t w;
} paillier_affine_range_pok_proof_t;

protocol_ctx_t *protocol_ctx_new();
void protocol_ctx_free(protocol_ctx_t *ctx);

void FiatSharir_hash(const uint8_t *data, const uint64_t data_len, uint8_t digest[FIAT_SHAMIR_DIGEST_BYTES]);

void group_multiplication(const protocol_ctx_t *ctx, const group_el_t a, const group_el_t b, group_el_t c);
void group_exponentiation(const protocol_ctx_t *ctx, const group_el_t a, const scalar_t exp, group_el_t c);
void group_pedersen_commitment(const protocol_ctx_t *ctx, const pedersen_exponents_t exps, group_el_t ped_com);

void group_pedersen_pok_sample    (const protocol_ctx_t *ctx, pedersen_exponents_t randomness);
void group_pedersen_pok_anchor    (const protocol_ctx_t *ctx, const pedersen_exponents_t randomness, group_pedersen_pok_anchor_t *anchor);
void group_pedersen_pok_challenge (const protocol_ctx_t *ctx, const group_pedersen_pok_public_t *params, const group_pedersen_pok_anchor_t *anchor, scalar_t challenge);
void group_pedersen_pok_prove     (const protocol_ctx_t *ctx, const group_pedersen_pok_public_t *params, const pedersen_exponents_t randomness, const pedersen_exponents_t secrets, group_pedersen_pok_proof_t *proof);
int  group_pedersen_pok_verify    (const protocol_ctx_t *ctx, const group_pedersen_pok_public_t *params, const group_pedersen_pok_proof_t *proof);

void dlog_group_pedersen_pok_sample   (const protocol_ctx_t *ctx, pedersen_exponents_t randomness);
void dlog_group_pedersen_pok_anchor   (const protocol_ctx_t *ctx, const pedersen_exponents_t randomness, const group_el_t Gamma, dlog_group_pedersen_pok_anchor_t *anchor);
void dlog_group_pedersen_pok_challenge(const protocol_ctx_t *ctx, const dlog_group_pedersen_pok_public_t *params, const dlog_group_pedersen_pok_anchor_t *anchor, scalar_t challenge);
void dlog_group_pedersen_pok_prove    (const protocol_ctx_t *ctx, const dlog_group_pedersen_pok_public_t *params, const pedersen_exponents_t randomness, const pedersen_exponents_t secrets, dlog_group_pedersen_pok_proof_t *proof);
int  dlog_group_pedersen_pok_verify   (const protocol_ctx_t *ctx, const dlog_group_pedersen_pok_public_t *params, const dlog_group_pedersen_pok_proof_t *proof);

void paillier_encryption_generate_keys  (const protocol_ctx_t *ctx, paillier_public_key_t *pub, paillier_private_key_t *priv);
void paillier_encryption_sample         (const protocol_ctx_t *ctx, scalar_t rho, int sample_coprime);
void paillier_encryption_encrypt        (const protocol_ctx_t *ctx, const paillier_public_key_t *pub, const scalar_t plaintext, scalar_t ciphertext);
void paillier_encryption_decrypt        (const protocol_ctx_t *ctx, const paillier_private_key_t *priv, const scalar_t ciphertext, scalar_t plaintext);
void paillier_encryption_homomorphic    (const protocol_ctx_t *ctx, const paillier_public_key_t *pub, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, scalar_t new_cipher);

void ring_pedersen_params_from_paillier(const protocol_ctx_t *ctx, const paillier_public_key_t *pub, ring_pedersen_parameters_t *params);
void ring_pedersen_commitment(const protocol_ctx_t *ctx, const ring_pedersen_parameters_t *ring_params, const pedersen_exponents_t exps, scalar_t ring_ped_com);

void paillier_range_pok_sample    (const protocol_ctx_t *ctx, const paillier_range_pok_public_t *params, paillier_range_pok_randomness_t *randomness, int sample_coprime);
void paillier_range_pok_anchor    (const protocol_ctx_t *ctx, const paillier_range_pok_public_t *params, const paillier_range_pok_randomness_t *randomness, paillier_range_pok_anchor_t *anchor);
void paillier_range_pok_challenge (const protocol_ctx_t *ctx, const paillier_range_pok_public_t *params, const paillier_range_pok_anchor_t *anchor, scalar_t challenge);
void paillier_range_pok_prove     (const protocol_ctx_t *ctx, const paillier_range_pok_public_t *params, const paillier_range_pok_randomness_t *randomness, const paillier_range_pok_secrets_t *secrets, paillier_range_pok_proof_t *proof);
int  paillier_range_pok_verify    (const protocol_ctx_t *ctx, const paillier_range_pok_public_t *params, const paillier_range_pok_proof_t *proof);

void paillier_affine_range_pok_sample    (const protocol_ctx_t *ctx, const paillier_affine_range_pok_public_t *params, paillier_affine_range_pok_randomness_t *randomness, int sample_coprime);
void paillier_affine_range_pok_anchor    (const protocol_ctx_t *ctx, const paillier_affine_range_pok_public_t *params, const paillier_affine_range_pok_randomness_t *randomness, paillier_affine_range_pok_anchor_t *anchor);
void paillier_affine_range_pok_challenge (const protocol_ctx_t *ctx, const paillier_affine_range_pok_public_t *params, const paillier_affine_range_pok_anchor_t *anchor, scalar_t challenge);
void paillier_affine_range_pok_prove     (const protocol_ctx_t *ctx, const paillier_affine_range_pok_public_t *params, const paillier_affine_range_pok_randomness_t *randomness, const paillier_affine_range_pok_secrets_t *secrets, paillier_affine_range_pok_proof_t *proof);
int  paillier_affine_range_pok_verify    (const protocol_ctx_t *ctx, const paillier_affine_range_pok_public_t *params, const paillier_affine_range_pok_proof_t *proof);
#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __SECP256K1_ALGEBRA_H__
