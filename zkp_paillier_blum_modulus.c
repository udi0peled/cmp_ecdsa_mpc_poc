#include "zkp_paillier_blum_modulus.h"

zkp_paillier_blum_modulus_proof_t *zkp_paillier_blum_new ()
{
  zkp_paillier_blum_modulus_proof_t *proof = malloc(sizeof(zkp_paillier_blum_modulus_proof_t));

  proof->w = scalar_new();

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    proof->x[i] = scalar_new();
    proof->z[i] = scalar_new();
  }

  memset(proof->a, 0x00, STATISTICAL_SECURITY);
  memset(proof->b, 0x00, STATISTICAL_SECURITY);

  return proof;
}

void  zkp_paillier_blum_free (zkp_paillier_blum_modulus_proof_t *proof)
{
  scalar_free(proof->w);

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_free(proof->x[i]);
    scalar_free(proof->z[i]);
  }

  memset(proof->a, 0x00, STATISTICAL_SECURITY);
  memset(proof->b, 0x00, STATISTICAL_SECURITY);

  free(proof);
}

void  zkp_paillier_blum_challenge (scalar_t y[STATISTICAL_SECURITY], zkp_paillier_blum_modulus_proof_t *proof, const scalar_t N_modulus, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on (paillier_pub_N, w).
  
  uint64_t fs_data_len = aux->info_len + 2*PAILLIER_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES, N_modulus, 1);
  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES, proof->w, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(y, STATISTICAL_SECURITY, N_modulus, fs_data, fs_data_len);

  free(fs_data);

}

void  zkp_paillier_blum_prove  (zkp_paillier_blum_modulus_proof_t *proof, const paillier_private_key_t *private, const zkp_aux_info_t *aux)
{
  assert(BN_num_bytes(private->N) == PAILLIER_MODULUS_BYTES);

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  // Generate random w with (-1, 1) Jacobi signs wrt (p,q)
  // Use CRT to set w as -a^2 mod q and b^2 mod q for uniform a,b

  scalar_t crt_mod_q_factor = scalar_new();
  scalar_t crt_mod_p_factor = scalar_new();
  scalar_t w_p_part = scalar_new();
  scalar_t w_q_part = scalar_new();

  BN_mod_inverse(crt_mod_q_factor, private->p, private->q, bn_ctx);
  BN_mod_inverse(crt_mod_p_factor, private->q, private->p, bn_ctx);
  BN_mod_mul(crt_mod_q_factor, crt_mod_q_factor, private->p, private->N, bn_ctx);
  BN_mod_mul(crt_mod_p_factor, crt_mod_p_factor, private->q, private->N, bn_ctx);

  BN_rand_range(w_p_part, private->p);
  BN_rand_range(w_q_part, private->q);
  BN_mod_sqr(w_p_part, w_p_part, private->p, bn_ctx);
  BN_mod_sqr(w_q_part, w_q_part, private->q, bn_ctx);
  BN_mod_mul(w_p_part, w_p_part, crt_mod_p_factor, private->N, bn_ctx);
  BN_mod_mul(w_q_part, w_q_part, crt_mod_q_factor, private->N, bn_ctx);

  BN_mod_sub(proof->w, w_q_part, w_p_part, private->N, bn_ctx);

  scalar_t y[STATISTICAL_SECURITY];
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i) y[i] = scalar_new();

  zkp_paillier_blum_challenge(y, proof, private->N, aux);

  // The following is needed to compute z[i]
  scalar_t N_inverse_mod_phiN = scalar_new();
  BN_mod_inverse(N_inverse_mod_phiN, private->N, private->phi_N, bn_ctx);    

  // We first compute each y[i] Legendre symbol pair (leg_q,leg_p) wrt (p,q), using Euler's Criterion (exp to (p-1)/2)
  // Then change y to be QR mod N by y_qr = (-1)^a * w^b * y where a = (leg_q == 1) and b = (leg_p != leg_q) (by choice of w with symbols (-1,1))
  // Then we can take y_qr's 4th root (wrt mod p and mod q seperately), by exponentation with ((prime+1)/4 mod (prime -1))
  // Lastly with randomize the 4th root by randomly changing the signs mod p and mod q (before CRT to compute the root mod N).

  scalar_t p_minus_1 = BN_dup(private->p);
  scalar_t q_minus_1 = BN_dup(private->q);

  BN_sub_word(p_minus_1, 1);
  BN_sub_word(q_minus_1, 1);

  scalar_t p_euler_exp = BN_dup(p_minus_1);
  scalar_t q_euler_exp = BN_dup(q_minus_1);

  BN_div_word(p_euler_exp, 2);
  BN_div_word(q_euler_exp, 2);

  scalar_t p_exp_4th_root = BN_dup(private->p);
  scalar_t q_exp_4th_root = BN_dup(private->q);

  BN_add_word(p_exp_4th_root, 1);
  BN_div_word(p_exp_4th_root, 4);
  BN_mod_sqr(p_exp_4th_root, p_exp_4th_root, p_minus_1, bn_ctx);

  BN_add_word(q_exp_4th_root, 1);
  BN_div_word(q_exp_4th_root, 4);
  BN_mod_sqr(q_exp_4th_root, q_exp_4th_root, q_minus_1, bn_ctx);

  scalar_t temp = scalar_new();
  scalar_t y_qr = scalar_new();
  scalar_t legendre_p = scalar_new();
  scalar_t legendre_q = scalar_new();
  scalar_t y_4th_root_mod_p = scalar_new();
  scalar_t y_4th_root_mod_q = scalar_new();

  // Sanity Check start...
    BN_mod_exp(temp, proof->w, p_euler_exp, private->p, bn_ctx);
    BN_mod_sub(temp, private->p, temp, private->p, bn_ctx);
    assert(BN_is_one(temp));
    BN_mod_exp(temp, proof->w, q_euler_exp, private->q, bn_ctx);
    assert(BN_is_one(temp));
  // ...end

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    BN_mod_exp(proof->z[i], y[i], N_inverse_mod_phiN, private->N, bn_ctx);

    // Compute Ledengre symbols of y, using Euler's criterion
    BN_mod_exp(legendre_p, y[i], p_euler_exp, private->p, bn_ctx);
    BN_mod_exp(legendre_q, y[i], q_euler_exp, private->q, bn_ctx);

    // Sanity checks start...
    assert(BN_is_one(legendre_p) != (BN_cmp(legendre_p, p_minus_1) == 0));
    assert(BN_is_one(legendre_q) != (BN_cmp(legendre_q, q_minus_1) == 0));
    // ...end

    // Derive a,b and compute fixed y_qr = (-1)^a * w^b * y

    proof->a[i] = BN_cmp(legendre_q, q_minus_1) == 0;
    proof->b[i] = (BN_is_one(legendre_p) && (BN_cmp(legendre_q, q_minus_1) == 0)) ||
                  (BN_is_one(legendre_q) && (BN_cmp(legendre_p, p_minus_1) == 0));

    BN_copy(y_qr, y[i]);
    if (proof->a[i]) BN_mod_sub(y_qr, private->N, y_qr, private->N, bn_ctx);
    if (proof->b[i]) BN_mod_mul(y_qr, proof->w, y_qr, private->N, bn_ctx);

    // Sanity Check start...
    BN_mod_exp(temp, y_qr, p_euler_exp, private->p, bn_ctx);
    assert(BN_is_one(temp));
    BN_mod_exp(temp, y_qr, q_euler_exp, private->q, bn_ctx);
    assert(BN_is_one(temp));
    // ...end

    // Compute x as random 4th root of fixed y_qr with CRT

    BN_mod_exp(y_4th_root_mod_p, y_qr, p_exp_4th_root, private->p, bn_ctx);
    BN_mod_exp(y_4th_root_mod_q, y_qr, q_exp_4th_root, private->q, bn_ctx);

    // Randomly change mod p and mod q components signs, to get random 4th root
    BN_rand(temp, 2, -1, 0);    // two random bits
    if (BN_is_bit_set(temp, 0)) BN_mod_sub(y_4th_root_mod_p, private->p, y_4th_root_mod_p, private->p, bn_ctx);
    if (BN_is_bit_set(temp, 1)) BN_mod_sub(y_4th_root_mod_q, private->q, y_4th_root_mod_q, private->q, bn_ctx);

    BN_mod_mul(y_4th_root_mod_p, y_4th_root_mod_p, crt_mod_p_factor, private->N, bn_ctx);
    BN_mod_mul(y_4th_root_mod_q, y_4th_root_mod_q, crt_mod_q_factor, private->N, bn_ctx);
    BN_mod_add(proof->x[i], y_4th_root_mod_p, y_4th_root_mod_q, private->N, bn_ctx);

    // Sanity Checks start...
    BN_mod_sqr(temp, proof->x[i], private->N, bn_ctx);
    BN_mod_sqr(temp, temp, private->N, bn_ctx);
    assert(BN_cmp(temp, y_qr) == 0);
    // ...end
  }

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i) scalar_free(y[i]);

  scalar_free(N_inverse_mod_phiN);
  scalar_free(y_4th_root_mod_p);
  scalar_free(y_4th_root_mod_q);
  scalar_free(q_exp_4th_root);
  scalar_free(p_exp_4th_root);
  scalar_free(p_minus_1);
  scalar_free(q_minus_1);
  scalar_free(crt_mod_q_factor);
  scalar_free(crt_mod_p_factor);
  scalar_free(temp);
  scalar_free(w_p_part);
  scalar_free(w_q_part);
  
  BN_CTX_free(bn_ctx);
}

int   zkp_paillier_blum_verify (zkp_paillier_blum_modulus_proof_t *proof, const paillier_public_key_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  // Check composite odd number of required byte-length
  int is_verified = BN_is_odd(public->N);
  is_verified &= (uint64_t) BN_num_bytes(public->N) == PAILLIER_MODULUS_BYTES;
  is_verified &= BN_is_prime_ex(public->N, 128, bn_ctx, NULL) == 0;

  scalar_t y[STATISTICAL_SECURITY];
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i) y[i] = scalar_new();
  
  zkp_paillier_blum_challenge(y, proof, public->N, aux);

  scalar_t lhs_value = scalar_new();

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    BN_mod_exp(lhs_value, proof->z[i], public->N, public->N, bn_ctx);
    is_verified &= scalar_equal(lhs_value, y[i]);

    BN_mod_sqr(lhs_value, proof->x[i], public->N, bn_ctx);
    BN_mod_sqr(lhs_value, lhs_value, public->N, bn_ctx);
    if (proof->b[i]) BN_mod_mul(y[i], proof->w, y[i], public->N, bn_ctx);
    if (proof->a[i]) BN_mod_sub(y[i], public->N, y[i], public->N, bn_ctx);
    is_verified &= scalar_equal(lhs_value, y[i]);
  }

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i) scalar_free(y[i]);
  scalar_free(lhs_value);
  BN_CTX_free(bn_ctx);

  return is_verified;
}

void zkp_paillier_blum_proof_to_bytes (uint8_t **bytes, uint64_t *byte_len, const zkp_paillier_blum_modulus_proof_t *proof, int move_to_end)
{
  uint64_t needed_byte_len = PAILLIER_MODULUS_BYTES*(1 + 2*STATISTICAL_SECURITY) + 2*STATISTICAL_SECURITY;

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *set_bytes = *bytes;
  
  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, proof->w, 1);
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, proof->x[i], 1);
    scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, proof->z[i], 1);
    
    memcpy(set_bytes, &proof->a[i], 1);       set_bytes += 1;
    memcpy(set_bytes, &proof->b[i], 1);       set_bytes += 1;
  }

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void zkp_paillier_blum_proof_from_bytes (zkp_paillier_blum_modulus_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, int move_to_end)
{
  uint64_t needed_byte_len;
  zkp_paillier_blum_proof_to_bytes(NULL, &needed_byte_len, NULL, 0);

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *read_bytes = *bytes;
  
  scalar_from_bytes(proof->w, &read_bytes, PAILLIER_MODULUS_BYTES, 1);
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_from_bytes(proof->x[i], &read_bytes, PAILLIER_MODULUS_BYTES, 1);
    scalar_from_bytes(proof->z[i], &read_bytes, PAILLIER_MODULUS_BYTES, 1);
    
    memcpy(&proof->a[i], read_bytes, 1);       read_bytes += 1;
    memcpy(&proof->b[i], read_bytes, 1);       read_bytes += 1;
  }

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}