#include "zkp_ring_pedersen_param.h"

zkp_ring_pedersen_param_proof_t *zkp_ring_pedersen_param_new ()
{
  zkp_ring_pedersen_param_proof_t *proof = malloc(sizeof(zkp_ring_pedersen_param_proof_t));

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    proof->A[i] = scalar_new();
    proof->z[i] = scalar_new();
  }

  return proof;
}

void zkp_ring_pedersen_param_free (zkp_ring_pedersen_param_proof_t *proof)
{
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_free(proof->A[i]);
    scalar_free(proof->z[i]);
  }

  free(proof);
}

void  zkp_ring_pedersen_param_challenge (uint8_t e[STATISTICAL_SECURITY], const zkp_ring_pedersen_param_proof_t *proof, const ring_pedersen_public_t *public, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on (N modulus, s, t, all A).

  uint64_t fs_data_len = aux->info_len + (STATISTICAL_SECURITY + 3) * RING_PED_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);       data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->s, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->t, 1);

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i) {
    scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , proof->A[i], 1);
  }

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_bytes(e, STATISTICAL_SECURITY, fs_data, fs_data_len);

  free(fs_data);
}

void  zkp_ring_pedersen_param_prove (zkp_ring_pedersen_param_proof_t *proof, const ring_pedersen_private_t *private, const zkp_aux_info_t *aux)
{
  assert(BN_num_bytes(private->N) == RING_PED_MODULUS_BYTES);
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  // Sample initial a_i as z_i (and computie commitment A[i]), so later will just add e_i*lam for final z_i.
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_sample_in_range(proof->z[i], private->phi_N, 0);
    BN_mod_exp(proof->A[i], private->t, proof->z[i], private->N, bn_ctx);
  }

  ring_pedersen_public_t public;
  public.N = private->N;
  public.s = private->s;
  public.t = private->t;

  uint8_t e[STATISTICAL_SECURITY];     // coin flips by LSB
  zkp_ring_pedersen_param_challenge(e, proof, &public, aux);

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    if (e[i] & 0x01) BN_mod_add(proof->z[i], proof->z[i], private->lam, private->phi_N, bn_ctx);
  }

  BN_CTX_free(bn_ctx);
}

int   zkp_ring_pedersen_param_verify (const zkp_ring_pedersen_param_proof_t *proof, const ring_pedersen_public_t *public, const zkp_aux_info_t *aux)
{
  uint8_t e[STATISTICAL_SECURITY];
  zkp_ring_pedersen_param_challenge(e, proof, public, aux);

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();
  scalar_t temp;

  int is_verified = BN_num_bytes(public->N) == RING_PED_MODULUS_BYTES;

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    BN_mod_exp(lhs_value, public->t, proof->z[i], public->N, bn_ctx);

    temp = (scalar_t) BN_value_one();
    if (e[i] & 0x01) temp = public->s;

    BN_mod_mul(rhs_value, proof->A[i], temp, public->N, bn_ctx);

    is_verified &= scalar_equal(lhs_value, rhs_value);
  }  

  scalar_free(lhs_value);
  scalar_free(rhs_value);
  BN_CTX_free(bn_ctx);

  return is_verified;
}

void zkp_ring_pedersen_param_proof_to_bytes (uint8_t **bytes, uint64_t *byte_len, const zkp_ring_pedersen_param_proof_t *proof, int move_to_end)
{
  uint64_t needed_byte_len = 2*RING_PED_MODULUS_BYTES*STATISTICAL_SECURITY;

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *set_bytes = *bytes;
  
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->A[i], 1);
    scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->z[i], 1);
  }

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void zkp_ring_pedersen_param_proof_from_bytes (zkp_ring_pedersen_param_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, int move_to_end)
{
  uint64_t needed_byte_len;
  zkp_ring_pedersen_param_proof_to_bytes(NULL, &needed_byte_len, NULL, 0);

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *read_bytes = *bytes;
  
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_from_bytes(proof->A[i], &read_bytes, RING_PED_MODULUS_BYTES, 1);
    scalar_from_bytes(proof->z[i], &read_bytes, RING_PED_MODULUS_BYTES, 1);
  }

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}