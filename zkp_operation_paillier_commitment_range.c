#include "zkp_operation_paillier_commitment_range.h"

zkp_operation_paillier_commitment_range_t *zkp_operation_paillier_commitment_range_new()
{
  zkp_operation_paillier_commitment_range_t *zkp = malloc(sizeof(*zkp));

  zkp->proof.B_x  = scalar_new();
  zkp->proof.B_y  = scalar_new();
  zkp->proof.A    = scalar_new();
  zkp->proof.E    = scalar_new();
  zkp->proof.F    = scalar_new();
  zkp->proof.S    = scalar_new();
  zkp->proof.T    = scalar_new();
  zkp->proof.z_1  = scalar_new();
  zkp->proof.z_2  = scalar_new();
  zkp->proof.z_3  = scalar_new();
  zkp->proof.z_4  = scalar_new();
  zkp->proof.w    = scalar_new();
  zkp->proof.w_x  = scalar_new();
  zkp->proof.w_y  = scalar_new();

  return zkp;
}

void  zkp_operation_paillier_commitment_range_free   (zkp_operation_paillier_commitment_range_t *zkp)
{
  zkp->secret.x     = NULL;
  zkp->secret.y     = NULL;
  zkp->secret.rho   = NULL;
  zkp->secret.rho_x = NULL;
  zkp->secret.rho_y = NULL;

  scalar_free(zkp->proof.B_x);
  scalar_free(zkp->proof.B_y);
  scalar_free(zkp->proof.A);
  scalar_free(zkp->proof.E);
  scalar_free(zkp->proof.F);
  scalar_free(zkp->proof.S);
  scalar_free(zkp->proof.T);
  scalar_free(zkp->proof.z_1);
  scalar_free(zkp->proof.z_2);
  scalar_free(zkp->proof.z_3);
  scalar_free(zkp->proof.z_4);
  scalar_free(zkp->proof.w);
  scalar_free(zkp->proof.w_x);
  scalar_free(zkp->proof.w_y);

  free(zkp);
}

void zkp_operation_paillier_commitment_range_challenge (scalar_t e, zkp_operation_paillier_commitment_range_t *zkp, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on paillier_N_0 paillier_N_1, rped_N_s_t, g, C, D, Y, X, A, B_x, B_y, E, F, S, T

  uint64_t fs_data_len = aux->info_len + 16*PAILLIER_MODULUS_BYTES + 7*RING_PED_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);       data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , zkp->public.paillier_pub_0->N, 1);
  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , zkp->public.paillier_pub_1->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->s, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->t, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->public.X, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->public.C, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->public.Y, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->public.D, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->proof.B_x, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->proof.B_y, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->proof.A, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, zkp->proof.E, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, zkp->proof.F, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, zkp->proof.S, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, zkp->proof.T, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(zkp->public.G), fs_data, fs_data_len);
  scalar_make_signed(e, ec_group_order(zkp->public.G));

  free(fs_data);
}


void zkp_operation_paillier_commitment_range_prove (zkp_operation_paillier_commitment_range_t *zkp, const zkp_aux_info_t *aux)
{
  if ((uint64_t) BN_num_bytes(zkp->secret.x) > zkp->public.x_range_bytes) return;
  if ((uint64_t) BN_num_bytes(zkp->secret.y) > zkp->public.y_range_bytes) return;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t alpha_range = scalar_new();
  scalar_t beta_range  = scalar_new();
  scalar_t gamma_range = scalar_new();    // Also delta range
  scalar_t mu_range    = scalar_new();    // Also m range
  scalar_t alpha       = scalar_new();
  scalar_t beta        = scalar_new();
  scalar_t gamma       = scalar_new();
  scalar_t delta       = scalar_new();
  scalar_t mu          = scalar_new();
  scalar_t m           = scalar_new();
  scalar_t r           = scalar_new();
  scalar_t r_x         = scalar_new();
  scalar_t r_y         = scalar_new();
  scalar_t e           = scalar_new();
  scalar_t temp        = scalar_new();

  BN_set_bit(alpha_range, 8*zkp->public.x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(alpha, alpha_range, 0);
  scalar_make_signed(alpha, alpha_range);

  BN_set_bit(beta_range, 8*zkp->public.y_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(beta, beta_range, 0);
  scalar_make_signed(beta, beta_range);

  BN_set_bit(gamma_range, 8*zkp->public.x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  BN_mul(gamma_range, gamma_range, zkp->public.rped_pub->N, bn_ctx);
  scalar_sample_in_range(gamma, gamma_range, 0);
  scalar_make_signed(gamma, gamma_range);
  scalar_sample_in_range(delta, gamma_range, 0);
  scalar_make_signed(delta, gamma_range);
  
  BN_set_bit(mu_range, 8*zkp->public.x_range_bytes);
  BN_mul(mu_range, mu_range, zkp->public.rped_pub->N, bn_ctx);
  scalar_sample_in_range(mu, mu_range, 0);
  scalar_make_signed(mu, mu_range);
  scalar_sample_in_range(m, mu_range, 0);
  scalar_make_signed(m, mu_range);

  paillier_encryption_sample(r_x, zkp->public.paillier_pub_1);
  paillier_encryption_encrypt(zkp->proof.B_x, alpha, r_x, zkp->public.paillier_pub_1);

  paillier_encryption_sample(r_y, zkp->public.paillier_pub_1);
  paillier_encryption_encrypt(zkp->proof.B_y, beta, r_y, zkp->public.paillier_pub_1);

  paillier_encryption_sample(r, zkp->public.paillier_pub_0);
  paillier_encryption_encrypt(temp, beta, r, zkp->public.paillier_pub_0);
  scalar_exp(zkp->proof.A, zkp->public.C, alpha, zkp->public.paillier_pub_0->N2);
  scalar_mul(zkp->proof.A, zkp->proof.A, temp, zkp->public.paillier_pub_0->N2);

  ring_pedersen_commit(zkp->proof.E, alpha, gamma, zkp->public.rped_pub);
  ring_pedersen_commit(zkp->proof.F, beta, delta, zkp->public.rped_pub);
  ring_pedersen_commit(zkp->proof.S, zkp->secret.x, m, zkp->public.rped_pub);
  ring_pedersen_commit(zkp->proof.T, zkp->secret.y, mu, zkp->public.rped_pub);

  zkp_operation_paillier_commitment_range_challenge(e, zkp, aux);
  
  BN_mul(temp, e, zkp->secret.x, bn_ctx);
  BN_add(zkp->proof.z_1, alpha, temp);

  BN_mul(temp, e, zkp->secret.y, bn_ctx);
  BN_add(zkp->proof.z_2, beta, temp);

  BN_mul(temp, e, m, bn_ctx);
  BN_add(zkp->proof.z_3, gamma, temp);

  BN_mul(temp, e, mu, bn_ctx);
  BN_add(zkp->proof.z_4, delta, temp);

  scalar_exp(temp, zkp->secret.rho, e, zkp->public.paillier_pub_0->N);
  scalar_mul(zkp->proof.w, r, temp, zkp->public.paillier_pub_0->N);

  scalar_exp(temp, zkp->secret.rho_x, e, zkp->public.paillier_pub_1->N);
  scalar_mul(zkp->proof.w_x, r_x, temp, zkp->public.paillier_pub_1->N);

  scalar_exp(temp, zkp->secret.rho_y, e, zkp->public.paillier_pub_1->N);
  scalar_mul(zkp->proof.w_y, r_y, temp, zkp->public.paillier_pub_1->N);
  
  scalar_free(temp);
  scalar_free(e);
  scalar_free(r_y);
  scalar_free(r_x);
  scalar_free(r);
  scalar_free(m);
  scalar_free(mu);
  scalar_free(delta);
  scalar_free(gamma);
  scalar_free(beta);
  scalar_free(alpha);
  scalar_free(mu_range);
  scalar_free(gamma_range);
  scalar_free(beta_range);
  scalar_free(alpha_range);

  BN_CTX_free(bn_ctx);
}

int zkp_operation_paillier_commitment_range_verify (zkp_operation_paillier_commitment_range_t *zkp, const zkp_aux_info_t *aux)
{
  scalar_t z_1_range = scalar_new();
  scalar_t z_2_range = scalar_new();
  BN_set_bit(z_1_range, 8*zkp->public.x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);         // -1 since comparing signed range
  BN_set_bit(z_2_range, 8*zkp->public.y_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);

  int is_verified = (BN_ucmp(zkp->proof.z_1, z_1_range) < 0) && (BN_ucmp(zkp->proof.z_2, z_2_range) < 0);

  scalar_t e = scalar_new();
  zkp_operation_paillier_commitment_range_challenge(e, zkp, aux);

  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();
  scalar_t temp = scalar_new();
  
  paillier_encryption_encrypt(lhs_value, zkp->proof.z_1, zkp->proof.w_x, zkp->public.paillier_pub_1);
  scalar_exp(temp, zkp->public.X, e, zkp->public.paillier_pub_1->N2);
  scalar_mul(rhs_value, zkp->proof.B_x, temp, zkp->public.paillier_pub_1->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  paillier_encryption_encrypt(lhs_value, zkp->proof.z_2, zkp->proof.w_y, zkp->public.paillier_pub_1);
  scalar_exp(temp, zkp->public.Y, e, zkp->public.paillier_pub_1->N2);
  scalar_mul(rhs_value, zkp->proof.B_y, temp, zkp->public.paillier_pub_1->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);
  
  paillier_encryption_encrypt(temp, zkp->proof.z_2, zkp->proof.w, zkp->public.paillier_pub_0);
  scalar_exp(lhs_value, zkp->public.C, zkp->proof.z_1, zkp->public.paillier_pub_0->N2);
  scalar_mul(lhs_value, lhs_value, temp, zkp->public.paillier_pub_0->N2);
  scalar_exp(temp, zkp->public.D, e, zkp->public.paillier_pub_0->N2);
  scalar_mul(rhs_value, zkp->proof.A, temp, zkp->public.paillier_pub_0->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, zkp->proof.z_1, zkp->proof.z_3, zkp->public.rped_pub);
  scalar_exp(temp, zkp->proof.S, e, zkp->public.rped_pub->N);
  scalar_mul(rhs_value, zkp->proof.E, temp, zkp->public.rped_pub->N);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, zkp->proof.z_2, zkp->proof.z_4, zkp->public.rped_pub);
  scalar_exp(temp, zkp->proof.T, e, zkp->public.rped_pub->N);
  scalar_mul(rhs_value, zkp->proof.F, temp, zkp->public.rped_pub->N);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  scalar_free(e);
  scalar_free(temp);
  scalar_free(lhs_value);
  scalar_free(rhs_value);
  scalar_free(z_1_range);
  scalar_free(z_2_range);

  return is_verified;
}

void zkp_operation_paillier_commitment_range_proof_to_bytes(uint8_t **bytes, uint64_t *byte_len, const zkp_operation_paillier_commitment_range_t *zkp, uint64_t x_range_bytes, uint64_t y_range_bytes, int move_to_end)
{
  uint64_t needed_byte_len = 6*RING_PED_MODULUS_BYTES + 9*PAILLIER_MODULUS_BYTES + 3*x_range_bytes + y_range_bytes + 4*EPS_ZKP_SLACK_PARAMETER_BYTES;

  if ((!bytes) || (!*bytes) || (!zkp) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *set_bytes = *bytes;

  uint64_t bytelen;
  scalar_t range = scalar_new();
  scalar_t unsigned_value = scalar_new();
 
  scalar_t mod_range = scalar_new();
  scalar_t unsigned_scalar = scalar_new();

  scalar_to_bytes(&set_bytes, 2 * PAILLIER_MODULUS_BYTES, zkp->proof.A, 1);
  scalar_to_bytes(&set_bytes, 2 * PAILLIER_MODULUS_BYTES, zkp->proof.B_x, 1);
  scalar_to_bytes(&set_bytes, 2 * PAILLIER_MODULUS_BYTES, zkp->proof.B_y, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.E, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.F, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.S, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.T, 1);
  
  // unsigned z_1 to unsigned bytes
  bytelen = x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, zkp->proof.z_1);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  // unsigned z_2 to unsigned bytes
  bytelen = y_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, zkp->proof.z_2);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  // unsigned z_3 to unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, zkp->proof.z_3);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  // unsigned z_4 to unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, zkp->proof.z_4);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, zkp->proof.w, 1);
  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, zkp->proof.w_x, 1);
  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, zkp->proof.w_y, 1);

  scalar_free(range);
  scalar_free(unsigned_value);

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void zkp_operation_paillier_commitment_range_proof_from_bytes(zkp_operation_paillier_commitment_range_t *zkp, uint8_t **bytes, uint64_t *byte_len, uint64_t x_range_bytes, uint64_t y_range_bytes, int move_to_end)
{
  uint64_t needed_byte_len;
  zkp_operation_paillier_commitment_range_proof_to_bytes(NULL, &needed_byte_len, NULL, x_range_bytes, y_range_bytes, 0);

  if ((!bytes) || (!*bytes) || (!zkp) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *read_bytes = *bytes;

  uint64_t bytelen;
  scalar_t range = scalar_new();
 
  scalar_from_bytes(zkp->proof.A, &read_bytes, 2 * PAILLIER_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.B_x, &read_bytes, 2 * PAILLIER_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.B_y, &read_bytes, 2 * PAILLIER_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.E, &read_bytes, RING_PED_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.F, &read_bytes, RING_PED_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.S, &read_bytes, RING_PED_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.T, &read_bytes, RING_PED_MODULUS_BYTES, 1);

  // Signed z_1 from unsigned bytes
  bytelen = x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(zkp->proof.z_1, &read_bytes, bytelen, 1);
  scalar_make_signed(zkp->proof.z_1, range);

  // Signed z_2 from unsigned bytes
  bytelen = y_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(zkp->proof.z_2, &read_bytes, bytelen, 1);
  scalar_make_signed(zkp->proof.z_2, range);

  // Signed z_3 from unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(zkp->proof.z_3, &read_bytes, bytelen, 1);
  scalar_make_signed(zkp->proof.z_3, range);

  // Signed z_4 from unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(zkp->proof.z_4, &read_bytes, bytelen, 1);
  scalar_make_signed(zkp->proof.z_4, range);

  scalar_from_bytes(zkp->proof.w, &read_bytes, PAILLIER_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.w_x, &read_bytes, PAILLIER_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.w_y, &read_bytes, PAILLIER_MODULUS_BYTES, 1);

  scalar_free(range);

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}