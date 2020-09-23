#include "zkp_operation_group_commitment_range.h"

zkp_oper_group_commit_range_proof_t *zkp_oper_group_commit_range_new(const ec_group_t G)
{
  zkp_oper_group_commit_range_proof_t *proof = malloc(sizeof(zkp_oper_group_commit_range_proof_t));

  proof->B_x  = group_elem_new(G);
  proof->B_y  = scalar_new();
  proof->A    = scalar_new();
  proof->E    = scalar_new();
  proof->F    = scalar_new();
  proof->S    = scalar_new();
  proof->T    = scalar_new();
  proof->z_1  = scalar_new();
  proof->z_2  = scalar_new();
  proof->z_3  = scalar_new();
  proof->z_4  = scalar_new();
  proof->w    = scalar_new();
  proof->w_y  = scalar_new();

  return proof;
}

void  zkp_oper_group_commit_range_free   (zkp_oper_group_commit_range_proof_t *proof)
{
  group_elem_free(proof->B_x);
  scalar_free(proof->B_y);
  scalar_free(proof->A);
  scalar_free(proof->E);
  scalar_free(proof->F);
  scalar_free(proof->S);
  scalar_free(proof->T);
  scalar_free(proof->z_1);
  scalar_free(proof->z_2);
  scalar_free(proof->z_3);
  scalar_free(proof->z_4);
  scalar_free(proof->w);
  scalar_free(proof->w_y);

  free(proof);
}

void zkp_oper_group_commit_range_challenge (scalar_t e, const zkp_oper_group_commit_range_proof_t *proof, const zkp_oper_group_commit_range_public_t *public, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on paillier_N_0 paillier_N_1, rped_N_s_t, g, C, D, Y, X, A, B_x, B_y, E, F, S, T

  uint64_t fs_data_len = aux->info_len + 3*GROUP_ELEMENT_BYTES + 12*PAILLIER_MODULUS_BYTES + 7*RING_PED_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;
  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , public->paillier_pub_0->N, 1);
  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , public->paillier_pub_1->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->s, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->t, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->g, public->G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->X, public->G, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->C, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->Y, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->D, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->B_x, public->G, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, proof->B_y, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, proof->A, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->E, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->F, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->S, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->T, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(public->G), fs_data, fs_data_len);
  scalar_make_signed(e, ec_group_order(public->G));

  free(fs_data);
}


void zkp_oper_group_commit_range_prove (zkp_oper_group_commit_range_proof_t *proof, const zkp_oper_group_commit_range_secret_t *secret, const zkp_oper_group_commit_range_public_t *public, const zkp_aux_info_t *aux)
{
  assert((unsigned) BN_num_bytes(secret->x) <= public->x_range_bytes);
  assert((unsigned) BN_num_bytes(secret->y) <= public->y_range_bytes);

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
  scalar_t r_y         = scalar_new();
  scalar_t e           = scalar_new();
  scalar_t temp        = scalar_new();

  BN_set_bit(alpha_range, 8*public->x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(alpha, alpha_range, 0);
  scalar_make_signed(alpha, alpha_range);

  BN_set_bit(beta_range, 8*public->y_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(beta, beta_range, 0);
  scalar_make_signed(beta, beta_range);

  BN_set_bit(gamma_range, 8*public->x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  BN_mul(gamma_range, gamma_range, public->rped_pub->N, bn_ctx);
  scalar_sample_in_range(gamma, gamma_range, 0);
  scalar_make_signed(gamma, gamma_range);
  scalar_sample_in_range(delta, gamma_range, 0);
  scalar_make_signed(delta, gamma_range);
  
  BN_set_bit(mu_range, 8*public->x_range_bytes);
  BN_mul(mu_range, mu_range, public->rped_pub->N, bn_ctx);
  scalar_sample_in_range(mu, mu_range, 0);
  scalar_make_signed(mu, mu_range);
  scalar_sample_in_range(m, mu_range, 0);
  scalar_make_signed(m, mu_range);
  
  group_operation(proof->B_x, NULL, public->g, alpha, public->G);

  paillier_encryption_sample(r_y, public->paillier_pub_1);
  paillier_encryption_encrypt(proof->B_y, beta, r_y, public->paillier_pub_1);

  paillier_encryption_sample(r, public->paillier_pub_0);
  paillier_encryption_encrypt(temp, beta, r, public->paillier_pub_0);
  scalar_exp(proof->A, public->C, alpha, public->paillier_pub_0->N2);
  scalar_mul(proof->A, proof->A, temp, public->paillier_pub_0->N2);

  ring_pedersen_commit(proof->E, alpha, gamma, public->rped_pub);
  ring_pedersen_commit(proof->F, beta, delta, public->rped_pub);
  ring_pedersen_commit(proof->S, secret->x, m, public->rped_pub);
  ring_pedersen_commit(proof->T, secret->y, mu, public->rped_pub);

  zkp_oper_group_commit_range_challenge(e, proof, public, aux);
  
  BN_mul(temp, e, secret->x, bn_ctx);
  BN_add(proof->z_1, alpha, temp);

  BN_mul(temp, e, secret->y, bn_ctx);
  BN_add(proof->z_2, beta, temp);

  BN_mul(temp, e, m, bn_ctx);
  BN_add(proof->z_3, gamma, temp);

  BN_mul(temp, e, mu, bn_ctx);
  BN_add(proof->z_4, delta, temp);

  scalar_exp(temp, secret->rho, e, public->paillier_pub_0->N);
  scalar_mul(proof->w, r, temp, public->paillier_pub_0->N);

  scalar_exp(temp, secret->rho_y, e, public->paillier_pub_1->N);
  scalar_mul(proof->w_y, r_y, temp, public->paillier_pub_1->N);

  scalar_free(temp);
  scalar_free(e);
  scalar_free(r_y);
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

int zkp_oper_group_commit_range_verify  (const zkp_oper_group_commit_range_proof_t *proof, const zkp_oper_group_commit_range_public_t *public, const zkp_aux_info_t *aux)
{
  scalar_t z_1_range = scalar_new();
  scalar_t z_2_range = scalar_new();
  BN_set_bit(z_1_range, 8*public->x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);          // -1 since comparing signed range
  BN_set_bit(z_2_range, 8*public->y_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);

  int is_verified = (BN_ucmp(proof->z_1, z_1_range) < 0) && (BN_ucmp(proof->z_2, z_2_range) < 0);

  scalar_t e = scalar_new();
  zkp_oper_group_commit_range_challenge(e, proof, public, aux);

  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();
  scalar_t temp = scalar_new();

  paillier_encryption_encrypt(lhs_value, proof->z_2, proof->w_y, public->paillier_pub_1);
  scalar_exp(temp, public->Y, e, public->paillier_pub_1->N2);
  scalar_mul(rhs_value, proof->B_y, temp, public->paillier_pub_1->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  paillier_encryption_encrypt(temp, proof->z_2, proof->w, public->paillier_pub_0);
  scalar_exp(lhs_value, public->C, proof->z_1, public->paillier_pub_0->N2);
  scalar_mul(lhs_value, lhs_value, temp, public->paillier_pub_0->N2);
  scalar_exp(temp, public->D, e, public->paillier_pub_0->N2);
  scalar_mul(rhs_value, proof->A, temp, public->paillier_pub_0->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, proof->z_1, proof->z_3, public->rped_pub);
  scalar_exp(temp, proof->S, e, public->rped_pub->N);
  scalar_mul(rhs_value, proof->E, temp, public->rped_pub->N);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, proof->z_2, proof->z_4, public->rped_pub);
  scalar_exp(temp, proof->T, e, public->rped_pub->N);
  scalar_mul(rhs_value, proof->F, temp, public->rped_pub->N);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  gr_elem_t lhs_gr_elem = group_elem_new(public->G);
  gr_elem_t rhs_gr_elem = group_elem_new(public->G);

  group_operation(lhs_gr_elem, NULL, public->g, proof->z_1, public->G);
  group_operation(rhs_gr_elem, proof->B_x, public->X, e, public->G);
  is_verified &= group_elem_equal(lhs_gr_elem, rhs_gr_elem, public->G);

  scalar_free(e);
  scalar_free(temp);
  scalar_free(lhs_value);
  scalar_free(rhs_value);
  scalar_free(z_1_range);
  scalar_free(z_2_range);
  group_elem_free(lhs_gr_elem);
  group_elem_free(rhs_gr_elem);

  return is_verified;
}

void zkp_oper_group_commit_range_proof_to_bytes (uint8_t **bytes, uint64_t *byte_len, const zkp_oper_group_commit_range_proof_t *proof, uint64_t x_range_bytes, uint64_t y_range_bytes, const ec_group_t G, int move_to_end)
{
  uint64_t needed_byte_len = GROUP_ELEMENT_BYTES + 6*RING_PED_MODULUS_BYTES + 6*PAILLIER_MODULUS_BYTES + 3*x_range_bytes + y_range_bytes + 4*EPS_ZKP_SLACK_PARAMETER_BYTES;

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *set_bytes = *bytes;

  uint64_t bytelen;
  scalar_t range = scalar_new();
  scalar_t unsigned_value = scalar_new();
 
  scalar_to_bytes(&set_bytes, 2 * PAILLIER_MODULUS_BYTES, proof->A, 1);
  group_elem_to_bytes(&set_bytes, GROUP_ELEMENT_BYTES, proof->B_x, G, 1);
  scalar_to_bytes(&set_bytes, 2 * PAILLIER_MODULUS_BYTES, proof->B_y, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->E, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->F, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->S, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->T, 1);

  // unsigned z_1 to unsigned bytes
  bytelen = x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, proof->z_1);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  // unsigned z_2 to unsigned bytes
  bytelen = y_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, proof->z_2);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);
  
  // unsigned z_3 to unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, proof->z_3);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  // unsigned z_4 to unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, proof->z_4);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, proof->w, 1);
  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, proof->w_y, 1);

  scalar_free(range);
  scalar_free(unsigned_value);

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void zkp_oper_group_commit_range_proof_from_bytes(zkp_oper_group_commit_range_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, uint64_t x_range_bytes, uint64_t y_range_bytes, const scalar_t N0, const scalar_t N1, const ec_group_t G, int move_to_end)
{
  uint64_t needed_byte_len;
  zkp_oper_group_commit_range_proof_to_bytes(NULL, &needed_byte_len, NULL, x_range_bytes, y_range_bytes, G, 0);

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *read_bytes = *bytes;

  uint64_t bytelen;
  scalar_t range = scalar_new();
  
  scalar_coprime_from_bytes(proof->A, &read_bytes, 2 * PAILLIER_MODULUS_BYTES, N0, 1);
  group_elem_from_bytes(proof->B_x, &read_bytes, GROUP_ELEMENT_BYTES, G, 1);
  scalar_coprime_from_bytes(proof->B_y, &read_bytes, 2 * PAILLIER_MODULUS_BYTES, N1, 1);
  scalar_from_bytes(proof->E, &read_bytes, RING_PED_MODULUS_BYTES, 1);
  scalar_from_bytes(proof->F, &read_bytes, RING_PED_MODULUS_BYTES, 1);
  scalar_from_bytes(proof->S, &read_bytes, RING_PED_MODULUS_BYTES, 1);
  scalar_from_bytes(proof->T, &read_bytes, RING_PED_MODULUS_BYTES, 1);

  // Signed z_1 from unsigned bytes
  bytelen = x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(proof->z_1, &read_bytes, bytelen, 1);
  scalar_make_signed(proof->z_1, range);

  // Signed z_2 from unsigned bytes
  bytelen = y_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(proof->z_2, &read_bytes, bytelen, 1);
  scalar_make_signed(proof->z_2, range);

  // Signed z_3 from unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(proof->z_3, &read_bytes, bytelen, 1);
  scalar_make_signed(proof->z_3, range);

  // Signed z_4 from unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(proof->z_4, &read_bytes, bytelen, 1);
  scalar_make_signed(proof->z_4, range);

  scalar_coprime_from_bytes(proof->w, &read_bytes, PAILLIER_MODULUS_BYTES, N0, 1);
  scalar_coprime_from_bytes(proof->w_y, &read_bytes, PAILLIER_MODULUS_BYTES, N1, 1);

  scalar_free(range);

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}