#include "zkp_group_vs_paillier_range.h"

zkp_group_vs_paillier_range_t *zkp_group_vs_paillier_range_new()
{
  zkp_group_vs_paillier_range_t *zkp = malloc(sizeof(*zkp));

  zkp->proof.Y   = NULL;            // Group elements are created when proving
  zkp->proof.A   = scalar_new();
  zkp->proof.D   = scalar_new();
  zkp->proof.S   = scalar_new();
  zkp->proof.z_1 = scalar_new();
  zkp->proof.z_2 = scalar_new();
  zkp->proof.z_3 = scalar_new();

  return zkp;
}

void  zkp_group_vs_paillier_range_free   (zkp_group_vs_paillier_range_t *zkp)
{
  if (zkp->proof.Y) group_elem_free(zkp->proof.Y);
  scalar_free(zkp->proof.A);
  scalar_free(zkp->proof.D);
  scalar_free(zkp->proof.S);
  scalar_free(zkp->proof.z_1);
  scalar_free(zkp->proof.z_2);
  scalar_free(zkp->proof.z_3);

  free(zkp);
}

void zkp_group_vs_paillier_range_challenge (scalar_t e, zkp_group_vs_paillier_range_t *zkp, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on paillier_N, rped_N_s_t, g, X, C, Y, A, D, S

  uint64_t fs_data_len = aux->info_len + 3*GROUP_ELEMENT_BYTES + 5*PAILLIER_MODULUS_BYTES + 5*RING_PED_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);                                         data_pos += aux->info_len;

  scalar_to_bytes(data_pos, PAILLIER_MODULUS_BYTES , zkp->public.paillier_pub->N);    data_pos += PAILLIER_MODULUS_BYTES;
  scalar_to_bytes(data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->N);        data_pos += RING_PED_MODULUS_BYTES;
  scalar_to_bytes(data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->s);        data_pos += RING_PED_MODULUS_BYTES;
  scalar_to_bytes(data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->t);        data_pos += RING_PED_MODULUS_BYTES;
  
  group_elem_to_bytes(data_pos, GROUP_ELEMENT_BYTES, zkp->public.g, zkp->public.G);   data_pos += GROUP_ELEMENT_BYTES;
  group_elem_to_bytes(data_pos, GROUP_ELEMENT_BYTES, zkp->public.X, zkp->public.G);   data_pos += GROUP_ELEMENT_BYTES;
  scalar_to_bytes(data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->public.C);                 data_pos += 2*PAILLIER_MODULUS_BYTES;

  group_elem_to_bytes(data_pos, GROUP_ELEMENT_BYTES, zkp->proof.Y, zkp->public.G);    data_pos += GROUP_ELEMENT_BYTES;
  scalar_to_bytes(data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->proof.A);                  data_pos += 2*PAILLIER_MODULUS_BYTES;
  scalar_to_bytes(data_pos, RING_PED_MODULUS_BYTES, zkp->proof.D);                    data_pos += RING_PED_MODULUS_BYTES;
  scalar_to_bytes(data_pos, RING_PED_MODULUS_BYTES, zkp->proof.S);                    data_pos += RING_PED_MODULUS_BYTES;

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(zkp->public.G), fs_data, fs_data_len);
  scalar_make_plus_minus(e, ec_group_order(zkp->public.G));

  free(fs_data);
}


void zkp_group_vs_paillier_range_prove (zkp_group_vs_paillier_range_t *zkp, const zkp_aux_info_t *aux)
{
  if (!zkp->proof.Y) zkp->proof.Y = group_elem_new(zkp->public.G);
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t alpha_range = scalar_new();
  scalar_t gamma_range = scalar_new();
  scalar_t mu_range    = scalar_new();
  scalar_t alpha       = scalar_new();
  scalar_t gamma       = scalar_new();
  scalar_t mu          = scalar_new();
  scalar_t r           = scalar_new();
  scalar_t e           = scalar_new();

  BN_set_bit(alpha_range, 8*CALIGRAPHIC_I_ZKP_RANGE_BYTES + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(alpha, alpha_range, 0);
  scalar_make_plus_minus(alpha, alpha_range);

  BN_set_bit(gamma_range, 8*CALIGRAPHIC_I_ZKP_RANGE_BYTES + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  BN_mul(gamma_range, gamma_range, zkp->public.rped_pub->N, bn_ctx);
  scalar_sample_in_range(gamma, gamma_range, 0);
  scalar_make_plus_minus(gamma, gamma_range);
  
  BN_set_bit(mu_range, 8*CALIGRAPHIC_I_ZKP_RANGE_BYTES);
  BN_mul(mu_range, mu_range, zkp->public.rped_pub->N, bn_ctx);
  scalar_sample_in_range(mu, mu_range, 0);
  scalar_make_plus_minus(mu, mu_range);

  group_operation(zkp->proof.Y, NULL, zkp->public.g, zkp->secret.x, zkp->public.G);

  paillier_encryption_sample(r, zkp->public.paillier_pub);  
  paillier_encryption_encrypt(zkp->proof.A, alpha, r, zkp->public.paillier_pub);

  ring_pedersen_commit(zkp->proof.S, zkp->secret.x, mu, zkp->public.rped_pub);
  ring_pedersen_commit(zkp->proof.D, alpha, gamma, zkp->public.rped_pub);

  zkp_group_vs_paillier_range_challenge(e, zkp, aux);
  
  BN_mul(zkp->proof.z_1, e, zkp->secret.x, bn_ctx);
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

int   zkp_group_vs_paillier_range_verify (zkp_group_vs_paillier_range_t *zkp, const zkp_aux_info_t *aux)
{
  if (!zkp->proof.Y) zkp->proof.Y = group_elem_new(zkp->public.G);

  scalar_t z_1_range = scalar_new();
  BN_set_bit(z_1_range, 8*CALIGRAPHIC_I_ZKP_RANGE_BYTES + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);     // -1 since comparing signed range

  int is_verified = (BN_ucmp(zkp->proof.z_1, z_1_range) < 0);

  scalar_t e = scalar_new();
  zkp_group_vs_paillier_range_challenge(e, zkp, aux);

  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();

  paillier_encryption_encrypt(lhs_value, zkp->proof.z_1, zkp->proof.z_2, zkp->public.paillier_pub);
  scalar_exp(rhs_value, zkp->public.C, e, zkp->public.paillier_pub->N2);
  scalar_mul(rhs_value, zkp->proof.A, rhs_value, zkp->public.paillier_pub->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, zkp->proof.z_1, zkp->proof.z_3, zkp->public.rped_pub);
  scalar_exp(rhs_value, zkp->proof.S, e, zkp->public.rped_pub->N);
  scalar_mul(rhs_value, zkp->proof.D, rhs_value, zkp->public.rped_pub->N);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  gr_elem_t lhs_gr_elem = group_elem_new(zkp->public.G);
  gr_elem_t rhs_gr_elem = group_elem_new(zkp->public.G);

  group_operation(lhs_gr_elem, NULL, zkp->public.g, zkp->proof.z_1, zkp->public.G);
  group_operation(rhs_gr_elem, zkp->proof.Y, zkp->public.X, e, zkp->public.G);
  is_verified &= group_elem_equal(lhs_gr_elem, rhs_gr_elem, zkp->public.G);

  scalar_free(e);
  scalar_free(lhs_value);
  scalar_free(rhs_value);
  group_elem_free(lhs_gr_elem);
  group_elem_free(rhs_gr_elem);

  return is_verified;
}