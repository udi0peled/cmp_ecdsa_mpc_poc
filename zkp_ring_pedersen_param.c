#include "zkp_ring_pedersen_param.h"

zkp_ring_pedersen_param_t *zkp_ring_pedersen_param_new ()
{
  zkp_ring_pedersen_param_t *zkp = malloc(sizeof(*zkp));

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    zkp->proof.A[i] = scalar_new();
    zkp->proof.z[i] = scalar_new();
  }

  return zkp;
}

void zkp_ring_pedersen_param_free (zkp_ring_pedersen_param_t *zkp)
{
  zkp->secret = NULL;

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_free(zkp->proof.A[i]);
    scalar_free(zkp->proof.z[i]);
  }

  free(zkp);
}

void  zkp_ring_pedersen_param_challenge (uint8_t e[STATISTICAL_SECURITY], zkp_ring_pedersen_param_t *zkp, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on (N modulus, s, t, all A).

  uint64_t fs_data_len = aux->info_len + (STATISTICAL_SECURITY + 3) * RING_PED_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);       data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->rped_pub->s, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->rped_pub->t, 1);

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i) {
    scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->proof.A[i], 1);
  }

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_bytes(e, STATISTICAL_SECURITY, fs_data, fs_data_len);

  free(fs_data);
}

void  zkp_ring_pedersen_param_prove (zkp_ring_pedersen_param_t *zkp, const zkp_aux_info_t *aux)
{
  assert(BN_num_bytes(zkp->rped_pub->N) == RING_PED_MODULUS_BYTES);
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  // Sample initial a_i as z_i (and computie commitment A[i]), so later will just add e_i*lam for final z_i.
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_sample_in_range(zkp->proof.z[i], zkp->secret->phi_N, 0);
    BN_mod_exp(zkp->proof.A[i], zkp->rped_pub->t, zkp->proof.z[i], zkp->rped_pub->N, bn_ctx);
  }

  uint8_t e[STATISTICAL_SECURITY];                  // coin flips by LSB
  zkp_ring_pedersen_param_challenge(e, zkp, aux);

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    if (e[i] & 0x01) BN_mod_add(zkp->proof.z[i], zkp->proof.z[i], zkp->secret->lam, zkp->secret->phi_N, bn_ctx);
  }

  BN_CTX_free(bn_ctx);
}

int   zkp_ring_pedersen_param_verify (zkp_ring_pedersen_param_t *zkp, const zkp_aux_info_t *aux)
{
  uint8_t e[STATISTICAL_SECURITY];
  zkp_ring_pedersen_param_challenge(e, zkp, aux);

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();
  scalar_t temp;

  int is_verified = BN_num_bytes(zkp->rped_pub->N) == RING_PED_MODULUS_BYTES;

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    BN_mod_exp(lhs_value, zkp->rped_pub->t, zkp->proof.z[i], zkp->rped_pub->N, bn_ctx);

    temp = (scalar_t) BN_value_one();
    if (e[i] & 0x01) temp = zkp->rped_pub->s;

    BN_mod_mul(rhs_value, zkp->proof.A[i], temp, zkp->rped_pub->N, bn_ctx);

    is_verified &= scalar_equal(lhs_value, rhs_value);
  }  

  scalar_free(lhs_value);
  scalar_free(rhs_value);
  BN_CTX_free(bn_ctx);

  return is_verified;
}

void zkp_ring_pedersen_param_proof_to_bytes (uint8_t **bytes, uint64_t *byte_len, const zkp_ring_pedersen_param_t *zkp, int move_to_end)
{
  uint64_t needed_byte_len = 2*RING_PED_MODULUS_BYTES*STATISTICAL_SECURITY;

  if ((!bytes) || (!*bytes) || (!zkp) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *set_bytes = *bytes;
  
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.A[i], 1);
    scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.z[i], 1);
  }

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void zkp_ring_pedersen_param_proof_from_bytes (zkp_ring_pedersen_param_t *zkp, uint8_t **bytes, uint64_t *byte_len, int move_to_end)
{
  uint64_t needed_byte_len = 2*RING_PED_MODULUS_BYTES*STATISTICAL_SECURITY;

  if ((!bytes) || (!*bytes) || (!zkp) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *read_bytes = *bytes;
  
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_from_bytes(zkp->proof.A[i], &read_bytes, RING_PED_MODULUS_BYTES, 1);
    scalar_from_bytes(zkp->proof.z[i], &read_bytes, RING_PED_MODULUS_BYTES, 1);
  }

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}