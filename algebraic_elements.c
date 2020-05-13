#include "algebraic_elements.h"

scalar_t  scalar_new  ()             { return BN_secure_new(); }
void      scalar_free (scalar_t num) { BN_clear_free(num); }

void scalar_to_bytes(uint8_t *bytes, uint64_t byte_len, const scalar_t num)
{
  if (byte_len >= (uint64_t) BN_num_bytes(num))
    BN_bn2binpad(num, bytes, byte_len);
}


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

void scalar_exp (scalar_t result, const scalar_t base, const scalar_t exp, const scalar_t modulus)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  scalar_t res = scalar_new();
  //scalar_t pos_exp = BN_dup(exp);

  int invert = BN_is_negative(exp);
  
  // if exp negative, it ignores and uses positive
  BN_mod_exp(res, base, exp, modulus, bn_ctx);
  
  if (invert) BN_mod_inverse(res, res, modulus, bn_ctx);

  BN_copy(result, res);
  scalar_free(res);
  
  BN_CTX_free(bn_ctx);
}

int scalar_equal (const scalar_t a, const scalar_t b)
{
  return BN_cmp(a, b) == 0;
}

void scalar_make_plus_minus(scalar_t num, scalar_t num_range)
{
  scalar_t half_range = BN_dup(num_range);
  BN_div_word(half_range, 2);
  BN_sub(num, num, half_range);
  scalar_free(half_range);
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

void sample_safe_prime(scalar_t prime, unsigned int bits)
{
  BN_generate_prime_ex(prime, bits, 1, NULL, NULL, NULL);
}


/**
 *  Group and Group Elements
 */

ec_group_t  ec_group_new ()                     { return EC_GROUP_new_by_curve_name(GROUP_ID); }
void        ec_group_free (ec_group_t ec)       { EC_GROUP_free(ec); }
scalar_t    ec_group_order      (ec_group_t ec) { return (scalar_t) EC_GROUP_get0_order(ec); }

gr_elem_t   group_elem_new (const ec_group_t ec)  { return EC_POINT_new(ec); }
void        group_elem_free (gr_elem_t el)        { EC_POINT_clear_free(el); }

void group_elem_to_bytes (uint8_t *bytes, uint64_t byte_len, gr_elem_t el, const ec_group_t ec)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  EC_POINT_point2oct(ec, el, POINT_CONVERSION_COMPRESSED, bytes, byte_len, bn_ctx);
  BN_CTX_free(bn_ctx);
}

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

int group_elem_equal (const gr_elem_t a, const gr_elem_t b, const ec_group_t ec)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  int equal = EC_POINT_cmp(ec, a, b, bn_ctx) == 0;
  BN_CTX_free(bn_ctx);
  return equal;
}
