#include "zkp_encryption_in_range.h"

zkp_encryption_in_range_t *zkp_encryption_in_range_new ()
{
  zkp_encryption_in_range_t *zkp = malloc(sizeof(zkp_encryption_in_range_t));  
  
  zkp->proof.A    = scalar_new();
  zkp->proof.C    = scalar_new();
  zkp->proof.S    = scalar_new();
  zkp->proof.z_1  = scalar_new();
  zkp->proof.z_2  = scalar_new();
  zkp->proof.z_3  = scalar_new();

  return zkp;
}

void zkp_encryption_in_range_free (zkp_encryption_in_range_t *zkp)
{
  zkp->secret.k   = NULL;
  zkp->secret.rho = NULL;
  
  scalar_free(zkp->proof.A);
  scalar_free(zkp->proof.C);
  scalar_free(zkp->proof.S);
  scalar_free(zkp->proof.z_1);
  scalar_free(zkp->proof.z_2);
  scalar_free(zkp->proof.z_3);

  free(zkp);
}

void zkp_encryption_in_range_challenge (scalar_t e, zkp_encryption_in_range_t *zkp, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on paillier_N, rped_N_s_t, K, A, C, S
  uint64_t fs_data_len = aux->info_len + 5*RING_PED_MODULUS_BYTES + 5*PAILLIER_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , zkp->public.paillier_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->s, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->t, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES , zkp->public.K, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES , zkp->proof.A, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->proof.C, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->proof.S, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(zkp->public.G), fs_data, fs_data_len);
  scalar_make_signed(e, ec_group_order(zkp->public.G));

  free(fs_data);
}

void zkp_encryption_in_range_prove (zkp_encryption_in_range_t *zkp, const zkp_aux_info_t *aux)
{
  if ((uint64_t) BN_num_bytes(zkp->secret.k) > zkp->public.k_range_bytes) return;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t alpha_range = scalar_new();
  scalar_t gamma_range = scalar_new();
  scalar_t mu_range    = scalar_new();
  scalar_t alpha       = scalar_new();
  scalar_t gamma       = scalar_new();
  scalar_t mu          = scalar_new();
  scalar_t r           = scalar_new();
  scalar_t e           = scalar_new();

  BN_set_bit(alpha_range, 8*zkp->public.k_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(alpha, alpha_range, 0);
  scalar_make_signed(alpha, alpha_range);

  BN_set_bit(gamma_range, 8*zkp->public.k_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  BN_mul(gamma_range, gamma_range, zkp->public.rped_pub->N, bn_ctx);
  scalar_sample_in_range(gamma, gamma_range, 0);
  scalar_make_signed(gamma, gamma_range);
  
  BN_set_bit(mu_range, 8*zkp->public.k_range_bytes);
  BN_mul(mu_range, mu_range, zkp->public.rped_pub->N, bn_ctx);
  scalar_sample_in_range(mu, mu_range, 0);
  scalar_make_signed(mu, mu_range);
  
  paillier_encryption_sample(r, zkp->public.paillier_pub);
  paillier_encryption_encrypt(zkp->proof.A, alpha, r, zkp->public.paillier_pub);

  ring_pedersen_commit(zkp->proof.S, zkp->secret.k, mu, zkp->public.rped_pub);
  ring_pedersen_commit(zkp->proof.C, alpha, gamma, zkp->public.rped_pub);

  zkp_encryption_in_range_challenge(e, zkp, aux);
  
  BN_mul(zkp->proof.z_1, e, zkp->secret.k, bn_ctx);
  BN_add(zkp->proof.z_1, alpha, zkp->proof.z_1);
  
  scalar_exp(zkp->proof.z_2, zkp->secret.rho, e, zkp->public.paillier_pub->N);
  BN_mod_mul(zkp->proof.z_2, r, zkp->proof.z_2, zkp->public.paillier_pub->N, bn_ctx);

  BN_mul(zkp->proof.z_3, e, mu, bn_ctx);
  BN_add(zkp->proof.z_3, gamma, zkp->proof.z_3);
  
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

int zkp_encryption_in_range_verify (zkp_encryption_in_range_t *zkp, const zkp_aux_info_t *aux)
{
  scalar_t z_1_range = scalar_new();
  BN_set_bit(z_1_range, 8*zkp->public.k_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);     // -1 since comparing signed range

  int is_verified = (BN_ucmp(zkp->proof.z_1, z_1_range) < 0);

  scalar_t e = scalar_new();
  zkp_encryption_in_range_challenge(e, zkp, aux);

  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();

  paillier_encryption_encrypt(lhs_value, zkp->proof.z_1, zkp->proof.z_2, zkp->public.paillier_pub);
  scalar_exp(rhs_value, zkp->public.K, e, zkp->public.paillier_pub->N2);
  scalar_mul(rhs_value, zkp->proof.A, rhs_value, zkp->public.paillier_pub->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, zkp->proof.z_1, zkp->proof.z_3, zkp->public.rped_pub);  
  scalar_exp(rhs_value, zkp->proof.S, e, zkp->public.rped_pub->N);
  scalar_mul(rhs_value, zkp->proof.C, rhs_value, zkp->public.rped_pub->N);
  is_verified &= scalar_equal(lhs_value, rhs_value);
  
  scalar_free(e);
  scalar_free(z_1_range);
  scalar_free(lhs_value);
  scalar_free(rhs_value);

  return is_verified;
}

void zkp_encryption_in_range_proof_to_bytes(uint8_t **bytes, uint64_t *byte_len, const zkp_encryption_in_range_t *zkp, uint64_t k_range_bytes, int move_to_end)
{ 
  uint64_t needed_byte_len = 3*RING_PED_MODULUS_BYTES + 3*PAILLIER_MODULUS_BYTES + 2*k_range_bytes + 2*EPS_ZKP_SLACK_PARAMETER_BYTES;

  if ((!bytes) || (!*bytes) || (!zkp) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *set_bytes = *bytes;

  uint64_t bytelen;
  scalar_t range = scalar_new();
  scalar_t unsigned_value = scalar_new();

  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.S, 1);
  scalar_to_bytes(&set_bytes, 2 * PAILLIER_MODULUS_BYTES, zkp->proof.A, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.C, 1);

  // Unsigned z_1 to unsigned bytes
  bytelen = k_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, zkp->proof.z_1);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, zkp->proof.z_2, 1);

  // Unsigned z_3 to unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + k_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_copy(unsigned_value, zkp->proof.z_3);
  scalar_make_unsigned(unsigned_value, range);
  scalar_to_bytes(&set_bytes, bytelen, unsigned_value, 1);

  scalar_free(range);
  scalar_free(unsigned_value);

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void zkp_encryption_in_range_proof_from_bytes(zkp_encryption_in_range_t *zkp, uint8_t **bytes, uint64_t *byte_len, uint64_t k_range_bytes, int move_to_end)
{ 
  uint64_t needed_byte_len = 3*RING_PED_MODULUS_BYTES + 3*PAILLIER_MODULUS_BYTES + 2*k_range_bytes + 2*EPS_ZKP_SLACK_PARAMETER_BYTES;

  if ((!bytes) || (!*bytes) || (!zkp) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *read_bytes = *bytes;

  uint64_t bytelen;
  scalar_t range = scalar_new();

  scalar_from_bytes(zkp->proof.S, &read_bytes, RING_PED_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.A, &read_bytes, 2 * PAILLIER_MODULUS_BYTES, 1);
  scalar_from_bytes(zkp->proof.C, &read_bytes, RING_PED_MODULUS_BYTES, 1);

  // Signed z_1 from unsigned bytes
  bytelen = k_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(zkp->proof.z_1, &read_bytes, bytelen, 1);
  scalar_make_signed(zkp->proof.z_1, range);

  scalar_from_bytes(zkp->proof.z_2, &read_bytes, PAILLIER_MODULUS_BYTES, 1);

  // Signed z_3 from unsigned bytes
  bytelen = RING_PED_MODULUS_BYTES + k_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES;
  scalar_set_power_of_2(range, 8*bytelen);
  scalar_from_bytes(zkp->proof.z_3, &read_bytes, bytelen, 1);
  scalar_make_signed(zkp->proof.z_3, range);
  
  scalar_free(range);
  
  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}