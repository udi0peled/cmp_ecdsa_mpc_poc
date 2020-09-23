#include "algebraic_elements.h"
#include <openssl/rand.h>
#include <assert.h>

scalar_t  scalar_new    ()                                  { return BN_secure_new(); }
void      scalar_free   (scalar_t num)                      { BN_clear_free(num); }
void      scalar_copy   (scalar_t copy, const scalar_t num) { BN_copy(copy, num); }
void      scalar_set_ul (scalar_t num, unsigned long val)   { BN_set_word(num, val); }

void scalar_set_power_of_2 (scalar_t num, uint64_t two_exp)
{
  BN_set_word(num, 0);
  BN_set_bit(num, two_exp);
}

void scalar_to_bytes(uint8_t **bytes, uint64_t byte_len, const scalar_t num, int move_to_end)
{
  BN_bn2binpad(num, *bytes, byte_len);
  if (move_to_end) *bytes += byte_len;
}

void scalar_from_bytes (scalar_t num, uint8_t **bytes, uint64_t byte_len, int move_to_end)
{
  BN_bin2bn(*bytes, byte_len, num);
  if (move_to_end) *bytes += byte_len;
}

void scalar_coprime_from_bytes (scalar_t num, uint8_t **bytes, uint64_t byte_len, const scalar_t modulus, int move_to_end)
{  
  scalar_from_bytes(num, bytes, byte_len, move_to_end);
  if (!scalar_coprime(num, modulus)) scalar_set_ul(num, 1);
}

void scalar_add (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BN_mod_add(result, first, second, modulus, bn_ctx);
  BN_CTX_free(bn_ctx);
}

void scalar_sub (scalar_t result, const scalar_t first, const scalar_t second, const scalar_t modulus)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BN_mod_sub(result, first, second, modulus, bn_ctx);
  BN_CTX_free(bn_ctx);
}

void scalar_negate (scalar_t result, const scalar_t num)
{
  BN_copy(result, num);
  BN_set_negative(result, !BN_is_negative(result));
}

void scalar_complement (scalar_t result, const scalar_t num, const scalar_t modulus)
{
  scalar_t zero = scalar_new();
  BN_zero(zero);
  scalar_sub(result, zero, num, modulus);
  scalar_free(zero);
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

void scalar_gcd (scalar_t result, const scalar_t first, const scalar_t second)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BN_gcd(result, first, second, bn_ctx);
  BN_CTX_free(bn_ctx);
}

int scalar_coprime (const scalar_t first, const scalar_t second)
{
  scalar_t gcd = scalar_new();
  scalar_gcd(gcd, first, second);
  int res = BN_is_one(gcd);
  scalar_free(gcd);
  return res;
}

void scalar_exp (scalar_t result, const scalar_t base, const scalar_t exp, const scalar_t modulus)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  scalar_t res = scalar_new();
  
  // If exp negative, it ignores and uses positive, and invert result (fail if result isn't coprime to modulus)
  BN_mod_exp(res, base, exp, modulus, bn_ctx);
  if (BN_is_negative(exp)) BN_mod_inverse(res, res, modulus, bn_ctx);

  BN_copy(result, res);
  scalar_free(res);
  
  BN_CTX_free(bn_ctx);
}

int scalar_equal (const scalar_t a, const scalar_t b)
{
  return BN_cmp(a, b) == 0;
}

int scalar_bitlength (const scalar_t a)
{
  return BN_num_bits(a);
}

void scalar_make_signed(scalar_t num, const scalar_t range)
{
  assert((BN_cmp(num, range) <= 0) && (BN_is_negative(num) == 0));

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  scalar_t half_range = BN_dup(range);
  BN_div_word(half_range, 2);

  if (BN_cmp(num, half_range) >= 0) BN_sub(num, num, range);
  
  scalar_free(half_range);
  BN_CTX_free(bn_ctx);
}

void scalar_make_unsigned(scalar_t num, const scalar_t range)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t half_range = BN_dup(range);
  BN_div_word(half_range, 2);

  if (BN_is_negative(num)) BN_add(num, num, range);

  assert((BN_cmp(num, range) <= 0) && (BN_is_negative(num) == 0));
  
  scalar_free(half_range);
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

/**
 *  EC Group 
 */

ec_group_t  ec_group_new        ()                    { return EC_GROUP_new_by_curve_name(GROUP_ID); }
void        ec_group_free       (ec_group_t ec)       { EC_GROUP_free(ec); }
scalar_t    ec_group_order      (const ec_group_t ec) { return (scalar_t) EC_GROUP_get0_order(ec); }
gr_elem_t   ec_group_generator  (const ec_group_t ec) { return (gr_elem_t) EC_GROUP_get0_generator(ec); }

/**
 *  Group Elements
 */

gr_elem_t   group_elem_new (const ec_group_t ec)                  { return EC_POINT_new(ec); }
void        group_elem_free (gr_elem_t el)                        { EC_POINT_clear_free(el); }
void        group_elem_copy (gr_elem_t copy, const gr_elem_t el)  { EC_POINT_copy(copy, el);}

void group_elem_to_bytes (uint8_t **bytes, uint64_t byte_len, gr_elem_t el, const ec_group_t ec, int move_to_end)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  EC_POINT_point2oct(ec, el, POINT_CONVERSION_COMPRESSED, *bytes, byte_len, bn_ctx);
  if (move_to_end) *bytes += byte_len;
  BN_CTX_free(bn_ctx);
}

int group_elem_from_bytes (gr_elem_t el, uint8_t **bytes, uint64_t byte_len, const ec_group_t ec, int move_to_end)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  int ret = EC_POINT_oct2point(ec, el, *bytes, byte_len, bn_ctx);
  if (move_to_end) *bytes += byte_len;
  BN_CTX_free(bn_ctx);
  return ret != 1;
}

/**
 *  Computes initial * base^exp. If initial == NULL, assume identity. If initial and base are set, exp==NULL means exp=1
 */
void group_operation (gr_elem_t result, const gr_elem_t initial, const gr_elem_t base, const scalar_t exp, const ec_group_t ec)
{
  if (!base) 
  {
    EC_POINT_set_to_infinity(ec, result);
    return;
  }

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  if (!initial)
  {
    EC_POINT_mul(ec, result, NULL, base, exp, bn_ctx);
  }
  else  // initial and base are set
  {
    if (!exp)
    {
      EC_POINT_add(ec, result, initial, base, bn_ctx);
    }
    else // exp also set
    {
      gr_elem_t temp_res = group_elem_new(ec);
      EC_POINT_mul(ec, temp_res, NULL, base, exp, bn_ctx);
      EC_POINT_add(ec, result, initial, temp_res, bn_ctx);
      group_elem_free(temp_res);
    }
  }
  
  BN_CTX_free(bn_ctx);
}

int group_elem_equal (const gr_elem_t a, const gr_elem_t b, const ec_group_t ec)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  int equal = EC_POINT_cmp(ec, a, b, bn_ctx) == 0;
  BN_CTX_free(bn_ctx);
  return equal;
}

int group_elem_is_ident(const gr_elem_t a, const ec_group_t ec)
{
  return EC_POINT_is_at_infinity(ec, a) == 1;
}

void group_elem_get_x (scalar_t x, const gr_elem_t point, const ec_group_t ec, scalar_t modulus)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  EC_POINT_get_affine_coordinates(ec, point, x, NULL, bn_ctx);
  BN_mod(x, x, modulus, bn_ctx);
  BN_CTX_free(bn_ctx);
}