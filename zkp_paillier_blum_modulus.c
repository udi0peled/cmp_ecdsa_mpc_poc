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

  // Generate w with (-1, 1) Jacobi signs wrt (p,q) by CRT

  scalar_t p_crt = scalar_new();
  scalar_t q_crt = scalar_new();

  BN_mod_inverse(p_crt, private->p, private->q, bn_ctx);
  BN_mod_inverse(q_crt, private->q, private->p, bn_ctx);
  BN_mod_mul(p_crt, p_crt, private->p, private->N, bn_ctx);
  BN_mod_mul(q_crt, q_crt, private->q, private->N, bn_ctx);
  BN_mod_sub(proof->w, p_crt, q_crt, private->N, bn_ctx);

  scalar_t y[STATISTICAL_SECURITY];
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i) y[i] = scalar_new();

  zkp_paillier_blum_challenge(y, proof, private->N, aux);

  scalar_t N_inverse_mod_phiN = scalar_new();
  BN_mod_inverse(N_inverse_mod_phiN, private->N, private->phi_N, bn_ctx);    // To compute z[i]

  // Taking each y[i] 4th root (by exponent which is ((p-1)/4)^2 mod (p -1) - double sqrt
  // Checking result^4 = y[i] or -y[i], which defined the legendre symbol

  scalar_t p_minus_1 = BN_dup(private->p);
  scalar_t q_minus_1 = BN_dup(private->q);

  BN_sub_word(p_minus_1, 1);
  BN_sub_word(q_minus_1, 1);

  scalar_t p_exp_4th = BN_dup(private->p);
  scalar_t q_exp_4th = BN_dup(private->q);

  BN_add_word(p_exp_4th, 1);
  BN_div_word(p_exp_4th, 4);
  BN_mod_sqr(p_exp_4th, p_exp_4th, p_minus_1, bn_ctx);

  BN_add_word(q_exp_4th, 1);
  BN_div_word(q_exp_4th, 4);
  BN_mod_sqr(q_exp_4th, q_exp_4th, q_minus_1, bn_ctx);

  scalar_t temp = scalar_new();
  scalar_t y_mod_p = scalar_new();
  scalar_t y_mod_q = scalar_new();
  scalar_t p_4th_root = scalar_new();
  scalar_t q_4th_root = scalar_new();
  scalar_t p_computed_y = scalar_new();   // The 4th root, to the 4th power, gives y up to legendre symbol mod prime
  scalar_t q_computed_y = scalar_new();

  uint8_t legendre_p;   // 0 is QR, 1 if QNR
  uint8_t legendre_q;

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    BN_mod_exp(proof->z[i], y[i], N_inverse_mod_phiN, private->N, bn_ctx);

    // Compute potential 4th root modulo prime, a get legendre symbol 0/1 using 4th power
    BN_mod(y_mod_p, y[i], private->p, bn_ctx);
    BN_mod_exp(p_4th_root, y_mod_p, p_exp_4th, private->p, bn_ctx);
    BN_mod_sqr(temp, p_4th_root, private->p, bn_ctx);
    BN_mod_sqr(p_computed_y, temp, private->p, bn_ctx);
    legendre_p = BN_cmp(p_computed_y, y_mod_p) != 0;

    BN_mod(y_mod_q, y[i], private->q, bn_ctx);
    BN_mod_exp(q_4th_root, y_mod_q, q_exp_4th, private->q, bn_ctx);
    BN_mod_sqr(temp, q_4th_root, private->q, bn_ctx);
    BN_mod_sqr(q_computed_y, temp, private->q, bn_ctx);
    legendre_q = BN_cmp(q_computed_y, y_mod_q) != 0;

    // CRT compute 4th root mod N (up to a,b later)
    BN_mod_mul(p_4th_root, p_4th_root, q_crt, private->N, bn_ctx);
    BN_mod_mul(q_4th_root, q_4th_root, p_crt, private->N, bn_ctx);
    BN_mod_add(proof->x[i], p_4th_root, q_4th_root, private->N, bn_ctx);

    // According to choice of w above with (-1, 1) ledendre mod (p,q), and (-1)^a factor
    proof->a[i] = legendre_q;                   
    proof->b[i] = legendre_q != legendre_p;
  }

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i) scalar_free(y[i]);

  scalar_free(N_inverse_mod_phiN);
  scalar_free(p_computed_y);
  scalar_free(q_computed_y);
  scalar_free(p_4th_root);
  scalar_free(q_4th_root);
  scalar_free(q_exp_4th);
  scalar_free(p_exp_4th);
  scalar_free(p_minus_1);
  scalar_free(q_minus_1);
  scalar_free(y_mod_q);
  scalar_free(y_mod_p);
  scalar_free(p_crt);
  scalar_free(q_crt);
  scalar_free(temp);
  
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