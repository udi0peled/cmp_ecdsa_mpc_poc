#include "zkp_schnorr.h"

// Only allocates (and later frees) proof fields, all other are assumed to be populated externally
zkp_schnorr_t *zkp_schnorr_new()
{
  zkp_schnorr_t *zkp = malloc(sizeof(*zkp));
  
  zkp->proof.A = NULL;            // group elements are created when proving
  zkp->proof.z = scalar_new();

  return zkp;
}

void zkp_schnorr_free (zkp_schnorr_t *zkp)
{
  zkp->secret.x = NULL;

  group_elem_free(zkp->proof.A);
  scalar_free(zkp->proof.z);
  free(zkp);
}

void zkp_schnorr_commit (zkp_schnorr_t *zkp, scalar_t alpha)
{
  if (!zkp->proof.A) zkp->proof.A = group_elem_new(zkp->public.G);      // group elements are allocated while proving/commiting

  scalar_sample_in_range(alpha, ec_group_order(zkp->public.G), 0);
  group_operation(zkp->proof.A, NULL, zkp->public.g, alpha, zkp->public.G);
}

void zkp_schnoor_challenge(scalar_t e, const zkp_schnorr_t *zkp, const zkp_aux_info_t *aux)
{
  uint64_t fs_data_len = aux->info_len + 3*GROUP_ELEMENT_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, zkp->public.g, zkp->public.G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, zkp->public.X, zkp->public.G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, zkp->proof.A, zkp->public.G, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(zkp->public.G), fs_data, fs_data_len);

  free(fs_data);
}

void zkp_schnorr_prove (zkp_schnorr_t *zkp, const zkp_aux_info_t *aux, const scalar_t alpha)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  scalar_t e = scalar_new();

  if (!zkp->proof.A) zkp->proof.A = group_elem_new(zkp->public.G);             // group elements are allocated while proving
  group_operation(zkp->proof.A, NULL, zkp->public.g, alpha, zkp->public.G);

  zkp_schnoor_challenge(e, zkp, aux);

  BN_mod_mul(zkp->proof.z, e, zkp->secret.x, ec_group_order(zkp->public.G), bn_ctx);
  BN_mod_add(zkp->proof.z, zkp->proof.z, alpha, ec_group_order(zkp->public.G), bn_ctx);

  scalar_free(e);
  BN_CTX_free(bn_ctx);
}

int zkp_schnorr_verify (zkp_schnorr_t *zkp, const zkp_aux_info_t *aux)
{
  if (!zkp->proof.A) zkp->proof.A = group_elem_new(zkp->public.G);
  
  scalar_t e = scalar_new();
  zkp_schnoor_challenge(e, zkp, aux);

  gr_elem_t lhs_value = group_elem_new(zkp->public.G);
  gr_elem_t rhs_value = group_elem_new(zkp->public.G);

  group_operation(lhs_value, NULL, zkp->public.g, zkp->proof.z, zkp->public.G);
  group_operation(rhs_value, zkp->proof.A, zkp->public.X, e, zkp->public.G);
  int is_verified = group_elem_equal(lhs_value, rhs_value, zkp->public.G);

  scalar_free(e);
  group_elem_free(lhs_value);
  group_elem_free(rhs_value);

  return is_verified;
}

void zkp_schnorr_proof_to_bytes (uint8_t **bytes, uint64_t *byte_len, const zkp_schnorr_t *zkp, int move_to_end)
{
  uint64_t needed_byte_len = GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES;

  if ((!bytes) || (!*bytes) || (!zkp) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }

  uint8_t *set_bytes = *bytes;
  
  group_elem_to_bytes(&set_bytes, GROUP_ELEMENT_BYTES, zkp->proof.A, zkp->public.G, 1);
  scalar_to_bytes(&set_bytes, GROUP_ORDER_BYTES, zkp->proof.z, 1);

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void zkp_schnorr_proof_from_bytes (zkp_schnorr_t *zkp, uint8_t **bytes, uint64_t *byte_len, int move_to_end)
{
  uint64_t needed_byte_len = GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES;

  if ((!bytes) || (!*bytes) || (!zkp) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  
  uint8_t *read_bytes = *bytes;
  
  group_elem_from_bytes(zkp->proof.A, &read_bytes, GROUP_ELEMENT_BYTES, zkp->public.G, 1);
  scalar_from_bytes(zkp->proof.z, &read_bytes, GROUP_ORDER_BYTES, 1);

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}