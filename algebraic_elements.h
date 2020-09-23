/**
 * 
 *  Name:
 *  algebraic_elements
 * 
 *  Description: 
 *  Working with basic algebraic elements: elliptic curve groups (multiplicative notation), ec group elements and modulus ring scalars.
 *  Most functions are just simple wrappers of corresponding openssl functions.
 *  Some functions are a bit more then a wrapper to openssl, and handle parameters in more care, e.g.:
 *  scalar_exp which supports negative exponenet (as opposed to openssl), and group_operation which allows for NULL parameters (see below).
 * 
 *  Usage:
 *  All three types (ec_group_t, gr_elem_t, scalar_t) have constructures/destructures <...>_new and <...>_free. Freeing NULL doesn't do anything.
 *  All scalars (especially in modulus ring) are returned as non-negative, aside from the functions scalar_negate and scalar_make_signed.
 *  In <...>_to_bytes functions, if byte_len is bigger then needed bytes for element encoding, bytes buffer is padded with zeros. If smaller, nothing is changed.
 * 
 */

#ifndef __CMP20_ECDSA_MPC_ALGEBRAIC_ELEMENTS_H__
#define __CMP20_ECDSA_MPC_ALGEBRAIC_ELEMENTS_H__

#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>

#define GROUP_ID NID_secp256k1
#define GROUP_ORDER_BYTES 32
#define GROUP_ELEMENT_BYTES 33

typedef EC_GROUP *ec_group_t;
typedef EC_POINT *gr_elem_t;
typedef BIGNUM *scalar_t;

scalar_t  scalar_new               ();
void      scalar_free              (scalar_t num);
void      scalar_copy              (scalar_t copy, const scalar_t num);
void      scalar_set_ul            (scalar_t num, unsigned long val);
void      scalar_sample_in_range   (scalar_t rnd, const scalar_t range_mod, int coprime);
void      scalar_set_power_of_2    (scalar_t num, uint64_t two_exp);
// If byte_len too small, does nothing
void      scalar_to_bytes          (uint8_t **bytes, uint64_t byte_len, const scalar_t num, int move_to_end);
void      scalar_from_bytes        (scalar_t num, uint8_t **bytes, uint64_t byte_len, int move_to_end);
void      scalar_coprime_from_bytes(scalar_t num, uint8_t **bytes, uint64_t byte_len, const scalar_t modulus, int move_to_end);
int       scalar_equal             (const scalar_t a, const scalar_t b);
int       scalar_bitlength         (const scalar_t a);
void      scalar_gcd               (scalar_t result, const scalar_t first, const scalar_t second);
int       scalar_coprime           (const scalar_t first, const scalar_t second);
void      scalar_add               (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus);
void      scalar_sub               (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus);
void      scalar_negate            (scalar_t result, const scalar_t num);
void      scalar_complement        (scalar_t result, const scalar_t num, const scalar_t modulus);
void      scalar_mul               (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus);
void      scalar_inv               (scalar_t result, const scalar_t num, const scalar_t modulus);
// Computes base^exp (mod modulus), supports exp negative coprime to modulus (fails if not coprime). 
void      scalar_exp               (scalar_t result, const scalar_t base, const scalar_t exp, const scalar_t modulus);
// Convert num (after modulus) from range  [0 ... modulus) to [-modulus/2 ... modulus/2) for modulos = 2^bits
void      scalar_make_signed       (scalar_t num, const scalar_t range);
// Inverse of scalar_make_signed
void      scalar_make_unsigned     (scalar_t num, const scalar_t range);


ec_group_t  ec_group_new        ();
void        ec_group_free       (ec_group_t ec);
scalar_t    ec_group_order      (const ec_group_t ec);
gr_elem_t   ec_group_generator  (const ec_group_t ec);

gr_elem_t   group_elem_new        (const ec_group_t ec);
void        group_elem_free       (gr_elem_t el);
void        group_elem_copy       (gr_elem_t copy, const gr_elem_t el);
int         group_elem_equal      (const gr_elem_t a, const gr_elem_t b, const ec_group_t ec);
int         group_elem_is_ident   (const gr_elem_t a, const ec_group_t ec);
void        group_elem_get_x      (scalar_t x, const gr_elem_t a, const ec_group_t ec, scalar_t modulus);
// If byte_len too small, does nothing
void        group_elem_to_bytes   (uint8_t **bytes, uint64_t byte_len, const gr_elem_t el, const ec_group_t ec, int move_to_end);
// Returns 0/1 for success/error
int         group_elem_from_bytes (gr_elem_t el, uint8_t **bytes, uint64_t byte_len, const ec_group_t ec, int move_to_end);
// Compute initial*(base^exp) in the group. base==NULL retuns identity element of the group. initial==NULL used as identity. exp==NULL used as 1.
void        group_operation       (gr_elem_t result, const gr_elem_t initial, const gr_elem_t base, const scalar_t exp, const ec_group_t ec);

#endif