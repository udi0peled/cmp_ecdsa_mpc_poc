#include "zkp_schnorr.h"

zkp_schnorr_t *zkp_schnorr_new()
{
  zkp_schnorr_t *zkp = malloc(sizeof(*zkp));
  
  zkp->proof.A = group_elem_new(zkp->public.G);
  zkp->proof.z = scalar_new();

  return zkp;
}

void zkp_schnorr_free (zkp_schnorr_t *zkp)
{
  group_elem_free(zkp->proof.A);
  scalar_free(zkp->proof.z);
  free(zkp);
}

void zkp_schnorr_commit (zkp_schnorr_t *zkp, scalar_t alpha)
{
  scalar_sample_in_range(alpha, ec_group_order(zkp->public.G), 0);
  group_operation(zkp->proof.A, NULL, &zkp->public.g, &alpha, 1, zkp->public.G);
}

void zkp_schnoor_challenge(scalar_t e, const zkp_schnorr_t *zkp, const zkp_aux_info_t *aux)
{
  uint64_t fs_data_len = aux->info_len + 3*GROUP_ELEMENT_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);                                          data_pos += aux->info_len;
  group_elem_to_bytes(data_pos, GROUP_ELEMENT_BYTES, zkp->public.g, zkp->public.G);    data_pos += GROUP_ELEMENT_BYTES;
  group_elem_to_bytes(data_pos, GROUP_ELEMENT_BYTES, zkp->public.X, zkp->public.G);    data_pos += GROUP_ELEMENT_BYTES;
  group_elem_to_bytes(data_pos, GROUP_ELEMENT_BYTES, zkp->proof.A, zkp->public.G);     data_pos += GROUP_ELEMENT_BYTES;

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(zkp->public.G), fs_data, fs_data_len);

  free(fs_data);
}

void zkp_schnorr_prove (zkp_schnorr_t *zkp, const zkp_aux_info_t *aux, const scalar_t alpha)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  scalar_t e = scalar_new();

  EC_POINT_mul(zkp->public.G, zkp->proof.A, NULL, zkp->public.g, alpha, bn_ctx);

  zkp_schnoor_challenge(e, zkp, aux);

  BN_mod_mul(zkp->proof.z, e, zkp->secret.x, ec_group_order(zkp->public.G), bn_ctx);
  BN_mod_add(zkp->proof.z, zkp->proof.z, alpha, ec_group_order(zkp->public.G), bn_ctx);

  scalar_free(e);
  BN_CTX_free(bn_ctx);
}

int zkp_schnorr_verify (zkp_schnorr_t *zkp, const zkp_aux_info_t *aux)
{
  scalar_t e = scalar_new();
  zkp_schnoor_challenge(e, zkp, aux);

  gr_elem_t temp_gr_elem[2];
  scalar_t  temp_scalars[2];

  gr_elem_t lhs_value = group_elem_new(zkp->public.G);
  gr_elem_t rhs_value = group_elem_new(zkp->public.G);

  group_operation(lhs_value, NULL, &zkp->public.g, &zkp->proof.z, 1, zkp->public.G);

  temp_gr_elem[0] = zkp->proof.A;
  temp_gr_elem[1] = zkp->public.X;
  temp_scalars[0] = (scalar_t) BN_value_one();
  temp_scalars[1] = e;

  group_operation(rhs_value, NULL, temp_gr_elem, temp_scalars, 2, zkp->public.G);

  int is_verified = group_elem_equal(lhs_value, rhs_value, zkp->public.G);

  scalar_free(e);
  group_elem_free(lhs_value);
  group_elem_free(rhs_value);

  return is_verified;
}


