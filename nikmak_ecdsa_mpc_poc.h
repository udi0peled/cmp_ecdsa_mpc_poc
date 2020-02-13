#ifndef __NIKMAK_ECDSA_MPC_POC_H__
#define __NIKMAK_ECDSA_MPC_POC_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif //__cplusplus

#define GROUP_ID NID_secp256k1
#define GROUP_ORDER_BYTES 32
#define GROUP_COMPRESSED_POINT_BYTES 33
#define GROUP_UNCOMPRESSED_POINT_BYTES 65
#define FIAT_SHAMIR_DIGEST_BYTES 32

typedef struct group_ctx group_ctx_t;
typedef struct paillier_public_key paillier_public_key_t;
typedef struct paillier_private_key paillier_private_key_t;
typedef struct group_element group_element_t;
typedef struct scalar scalar_t;

group_ctx_t *group_ctx_new();
void group_ctx_free(group_ctx_t *ctx);

void group_multiplication(group_ctx_t *ctx, group_element_t c, group_element_t a, group_element_t b);
void group_exponentiation(group_ctx_t *ctx, group_element_t c, group_element_t a, scalar_t exp);
void group_pedersen_commitment(group_ctx_t *ctx, group_element ped_com, scalar_t alpha, scalar_t beta);

void FiatSharir_hash(uint8_t digest[FIAT_SHAMIR_DIGEST_BYTES], uint8_t *history, uint64_t history_len);

#ifdef __cplusplus
}
#endif //__cplusplus

#endif //#ifndef __SECP256K1_ALGEBRA_H__
