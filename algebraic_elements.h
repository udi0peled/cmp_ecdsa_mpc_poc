#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#ifndef __CMP20_ECDSA_MPC_ALGEBRAIC_ELEMENTS_H__
#define __CMP20_ECDSA_MPC_ALGEBRAIC_ELEMENTS_H__

#define GROUP_ID NID_secp256k1
#define GROUP_ORDER_BYTES 32
#define GROUP_ELEMENT_BYTES 33

typedef EC_GROUP *ec_group_t;
typedef EC_POINT *gr_elem_t;
typedef BIGNUM *scalar_t;

scalar_t  scalar_new               ();
void      scalar_free              (scalar_t num);
void      scalar_to_bytes          (uint8_t *bytes, uint64_t byte_len, const scalar_t num);
void      scalar_copy              (scalar_t copy, const scalar_t num);
void      scalar_set               (scalar_t num, unsigned long val);
int       scalar_equal             (const scalar_t a, const scalar_t b);
int       scalar_bitlength         (const scalar_t a);
void      scalar_add               (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus);
void      scalar_sub               (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus);
void      scalar_neg               (scalar_t result, const scalar_t num, const scalar_t modulus);
void      scalar_mul               (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus);
void      scalar_inv               (scalar_t result, const scalar_t num, const scalar_t modulus);
void      scalar_exp               (scalar_t result, const scalar_t base, const scalar_t exp, const scalar_t modulus);
void      scalar_make_plus_minus   (scalar_t num, scalar_t num_range);
void      scalar_sample_in_range   (scalar_t rnd, const scalar_t range_mod, int coprime);
void      sample_safe_prime        (scalar_t prime, unsigned int bits);

ec_group_t  ec_group_new        ();
void        ec_group_free       (ec_group_t ec);
scalar_t    ec_group_order      (ec_group_t ec);
gr_elem_t   ec_group_generator  (ec_group_t ec);

gr_elem_t   group_elem_new      (const ec_group_t ec);
void        group_elem_free     (gr_elem_t el);
void        group_elem_to_bytes (uint8_t *bytes, uint64_t byte_len, gr_elem_t el, const ec_group_t ec);
void        group_elem_copy     (gr_elem_t copy, const gr_elem_t el);
void        group_operation     (gr_elem_t result, const gr_elem_t initial, const gr_elem_t base, const scalar_t exp, const ec_group_t ec);
int         group_elem_equal    (const gr_elem_t a, const gr_elem_t b, const ec_group_t ec);
int         group_elem_is_ident (const gr_elem_t a, const ec_group_t ec);

#endif