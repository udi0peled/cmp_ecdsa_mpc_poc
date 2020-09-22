#include "zkp_schnorr.h"

// Only allocates (and later frees) proof fields, all other are assumed to be populated externally
zkp_schnorr_proof_t *zkp_schnorr_new (const ec_group_t G)
{
  zkp_schnorr_proof_t *proof = malloc(sizeof(zkp_schnorr_proof_t));
  
  proof->A = group_elem_new(G);
  proof->z = scalar_new();

  return proof;
}

void zkp_schnorr_free (zkp_schnorr_proof_t *proof)
{
  group_elem_free(proof->A);
  scalar_free(proof->z);
  free(proof);
}

void  zkp_schnorr_commit (gr_elem_t commited_A, scalar_t alpha, const zkp_schnorr_public_t *public)
{
  scalar_sample_in_range(alpha, ec_group_order(public->G), 0);
  group_operation(commited_A, NULL, public->g, alpha, public->G);
}

void zkp_schnoor_challenge(scalar_t e, const zkp_schnorr_proof_t *proof, const zkp_schnorr_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t fs_data_len = aux->info_len + 3*GROUP_ELEMENT_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->g, public->G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->X, public->G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->A, public->G, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(public->G), fs_data, fs_data_len);

  free(fs_data);
}

void  zkp_schnorr_prove (zkp_schnorr_proof_t *proof, const scalar_t alpha, const zkp_schnorr_secret_t *secret, const zkp_schnorr_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  scalar_t e = scalar_new();

  group_operation(proof->A, NULL, public->g, alpha, public->G);

  zkp_schnoor_challenge(e, proof, public, aux);

  BN_mod_mul(proof->z, e, secret->x, ec_group_order(public->G), bn_ctx);
  BN_mod_add(proof->z, proof->z, alpha, ec_group_order(public->G), bn_ctx);

  scalar_free(e);
  BN_CTX_free(bn_ctx);
}

int   zkp_schnorr_verify (const zkp_schnorr_proof_t *proof, const zkp_schnorr_public_t *public, const zkp_aux_info_t *aux)
{
  scalar_t e = scalar_new();
  zkp_schnoor_challenge(e, proof, public, aux);

  gr_elem_t lhs_value = group_elem_new(public->G);
  gr_elem_t rhs_value = group_elem_new(public->G);

  group_operation(lhs_value, NULL, public->g, proof->z, public->G);
  group_operation(rhs_value, proof->A, public->X, e, public->G);
  int is_verified = group_elem_equal(lhs_value, rhs_value, public->G);

  scalar_free(e);
  group_elem_free(lhs_value);
  group_elem_free(rhs_value);

  return is_verified;
}

void  zkp_schnorr_proof_to_bytes   (uint8_t **bytes, uint64_t *byte_len, const zkp_schnorr_proof_t *proof, const ec_group_t G, int move_to_end)
{
  uint64_t needed_byte_len = GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES;

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }

  uint8_t *set_bytes = *bytes;
  
  group_elem_to_bytes(&set_bytes, GROUP_ELEMENT_BYTES, proof->A, G, 1);
  scalar_to_bytes(&set_bytes, GROUP_ORDER_BYTES, proof->z, 1);

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void  zkp_schnorr_proof_from_bytes (zkp_schnorr_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, const ec_group_t G, int move_to_end)
{
  uint64_t needed_byte_len = GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES;

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  
  uint8_t *read_bytes = *bytes;
  
  group_elem_from_bytes(proof->A, &read_bytes, GROUP_ELEMENT_BYTES, G, 1);
  scalar_from_bytes(proof->z, &read_bytes, GROUP_ORDER_BYTES, 1);

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}