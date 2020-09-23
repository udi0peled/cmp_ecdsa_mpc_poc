#include "zkp_group_vs_paillier_range.h"

zkp_group_vs_paillier_range_proof_t *zkp_group_vs_paillier_range_new (const ec_group_t G)
{
  zkp_group_vs_paillier_range_proof_t *proof = malloc(sizeof(zkp_group_vs_paillier_range_proof_t));

  proof->Y   = group_elem_new(G);            // Group elements are created when proving
  proof->A   = scalar_new();
  proof->D   = scalar_new();
  proof->S   = scalar_new();
  proof->z_1 = scalar_new();
  proof->z_2 = scalar_new();
  proof->z_3 = scalar_new();

  return proof;
}

void  zkp_group_vs_paillier_range_free   (zkp_group_vs_paillier_range_proof_t *proof)
{
  group_elem_free(proof->Y);
  scalar_free(proof->A);
  scalar_free(proof->D);
  scalar_free(proof->S);
  scalar_free(proof->z_1);
  scalar_free(proof->z_2);
  scalar_free(proof->z_3);

  free(proof);
}

void zkp_group_vs_paillier_range_challenge (scalar_t e, const zkp_group_vs_paillier_range_proof_t *proof, const zkp_group_vs_paillier_range_public_t *public, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on paillier_N, rped_N_s_t, g, X, C, Y, A, D, S

  uint64_t fs_data_len = aux->info_len + 3*GROUP_ELEMENT_BYTES + 5*PAILLIER_MODULUS_BYTES + 5*RING_PED_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , public->paillier_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->s, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->t, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->g, public->G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->X, public->G, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->C, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->Y, public->G, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, proof->A, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->D, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->S, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(public->G), fs_data, fs_data_len);
  scalar_make_signed(e, ec_group_order(public->G));

  free(fs_data);
}


void zkp_group_vs_paillier_range_prove (zkp_group_vs_paillier_range_proof_t *proof, const zkp_group_vs_paillier_range_secret_t *secret, const zkp_group_vs_paillier_range_public_t *public, const zkp_aux_info_t *aux)
{
  assert((unsigned) BN_num_bytes(secret->x) <= public->x_range_bytes);
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t alpha_range = scalar_new();
  scalar_t gamma_range = scalar_new();
  scalar_t mu_range    = scalar_new();
  scalar_t alpha       = scalar_new();
  scalar_t gamma       = scalar_new();
  scalar_t mu          = scalar_new();
  scalar_t r           = scalar_new();
  scalar_t e           = scalar_new();
  
  BN_set_bit(alpha_range, 8*public->x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(alpha, alpha_range, 0);
  scalar_make_signed(alpha, alpha_range);

  BN_set_bit(gamma_range, 8*public->x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  BN_mul(gamma_range, gamma_range, public->rped_pub->N, bn_ctx);
  scalar_sample_in_range(gamma, gamma_range, 0);
  scalar_make_signed(gamma, gamma_range);
  
  BN_set_bit(mu_range, 8*public->x_range_bytes);
  BN_mul(mu_range, mu_range, public->rped_pub->N, bn_ctx);
  scalar_sample_in_range(mu, mu_range, 0);
  scalar_make_signed(mu, mu_range);

  group_operation(proof->Y, NULL, public->g, alpha, public->G);

  paillier_encryption_sample(r, public->paillier_pub);  
  paillier_encryption_encrypt(proof->A, alpha, r, public->paillier_pub);

  ring_pedersen_commit(proof->S, secret->x, mu, public->rped_pub);
  ring_pedersen_commit(proof->D, alpha, gamma, public->rped_pub);
  
  zkp_group_vs_paillier_range_challenge(e, proof, public, aux);
  
  BN_mul(proof->z_1, e, secret->x, bn_ctx);
  BN_add(proof->z_1, alpha, proof->z_1);

  scalar_exp(proof->z_2, secret->rho, e, public->paillier_pub->N);
  BN_mod_mul(proof->z_2, r, proof->z_2, public->paillier_pub->N, bn_ctx);

  BN_mul(proof->z_3, e, mu, bn_ctx);
  BN_add(proof->z_3, gamma, proof->z_3);
  
  scalar_free(e);
  scalar_free(r);
  scalar_free(mu);
  scalar_free(gamma);
  scalar_free(alpha);
  scalar_free(mu_range);
  scalar_free(gamma_range);
  scalar_free(alpha_range);
  BN_CTX_free(bn_ctx);
}

int   zkp_group_vs_paillier_range_verify (const zkp_group_vs_paillier_range_proof_t *proof, const zkp_group_vs_paillier_range_public_t *public, const zkp_aux_info_t *aux)
{
  scalar_t z_1_range = scalar_new();
  BN_set_bit(z_1_range, 8*public->x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);     // -1 since comparing signed range

  int is_verified = (BN_ucmp(proof->z_1, z_1_range) < 0);

  scalar_t e = scalar_new();
  zkp_group_vs_paillier_range_challenge(e, proof, public, aux);

  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();

  paillier_encryption_encrypt(lhs_value, proof->z_1, proof->z_2, public->paillier_pub);
  scalar_exp(rhs_value, public->C, e, public->paillier_pub->N2);
  scalar_mul(rhs_value, proof->A, rhs_value, public->paillier_pub->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, proof->z_1, proof->z_3, public->rped_pub);
  scalar_exp(rhs_value, proof->S, e, public->rped_pub->N);
  scalar_mul(rhs_value, proof->D, rhs_value, public->rped_pub->N);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  gr_elem_t lhs_gr_elem = group_elem_new(public->G);
  gr_elem_t rhs_gr_elem = group_elem_new(public->G);
  
  group_operation(lhs_gr_elem, NULL, public->g, proof->z_1, public->G);
  group_operation(rhs_gr_elem, proof->Y, public->X, e, public->G);
  is_verified &= group_elem_equal(lhs_gr_elem, rhs_gr_elem, public->G);

  scalar_free(e);
  scalar_free(lhs_value);
  scalar_free(rhs_value);
  scalar_free(z_1_range);
  group_elem_free(lhs_gr_elem);
  group_elem_free(rhs_gr_elem);

  return is_verified;
}

void zkp_group_vs_paillier_range_proof_to_bytes(uint8_t **bytes, uint64_t *byte_len, const zkp_group_vs_paillier_range_proof_t *proof, uint64_t x_range_bytes, const ec_group_t G, int move_to_end)
{ 
  uint64_t needed_byte_len = GROUP_ELEMENT_BYTES + 3*RING_PED_MODULUS_BYTES + 3*PAILLIER_MODULUS_BYTES + 2*x_range_bytes + 2*EPS_ZKP_SLACK_PARAMETER_BYTES;

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }

  uint8_t *set_bytes = *bytes;

  uint64_t bytelen;
  scalar_t range = scalar_new();
  scalar_t unsigned_value = scalar_new();
  
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->S, 1);
  scalar_to_bytes(&set_bytes, 2 * PAILLIER_MODULUS_BYTES, proof->A, 1);
  group_elem_to_bytes(&set_bytes, GROUP_ELEMENT_BYTES, proof->Y, G, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->D, 1);

  // unsigned z_1 to unsigned bytes
  bytelen = x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, proof->z_1);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, proof->z_2, 1);
  
  // Unsigned z_3 to unsigned bytes 
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, proof->z_3);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);
  
  scalar_free(range);
  scalar_free(unsigned_value);

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}


void zkp_group_vs_paillier_range_proof_from_bytes(zkp_group_vs_paillier_range_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, uint64_t x_range_bytes, const scalar_t N0, const ec_group_t G, int move_to_end)
{ 
  uint64_t needed_byte_len;
  zkp_group_vs_paillier_range_proof_to_bytes(NULL, &needed_byte_len, NULL, x_range_bytes, G, 0);

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }

  uint8_t *read_bytes = *bytes;

  uint64_t bytelen;
  scalar_t range = scalar_new();

  scalar_from_bytes(proof->S, &read_bytes, RING_PED_MODULUS_BYTES, 1);
  scalar_coprime_from_bytes(proof->A, &read_bytes, 2 * PAILLIER_MODULUS_BYTES, N0, 1);
  group_elem_from_bytes(proof->Y, &read_bytes, GROUP_ELEMENT_BYTES, G, 1);
  scalar_from_bytes(proof->D, &read_bytes, RING_PED_MODULUS_BYTES, 1);
  
  // Signed z_1 from unsigned bytes
  bytelen = x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(proof->z_1, &read_bytes, bytelen, 1);
  scalar_make_signed(proof->z_1, range);

  scalar_coprime_from_bytes(proof->z_2, &read_bytes, PAILLIER_MODULUS_BYTES, N0, 1);

  // Signed z_3 from unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(proof->z_3, &read_bytes, bytelen, 1);
  scalar_make_signed(proof->z_3, range);
  
  scalar_free(range);
  
  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}