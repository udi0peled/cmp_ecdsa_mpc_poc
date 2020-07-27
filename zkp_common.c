#include <string.h>
#include <openssl/sha.h>

#include "zkp_common.h"

/**
 *  Fiat-Shamir / Random Oracle
 */

#define FS_HALF 32      // Half of SHA512 64 bytes digest

/** 
 *  Denote hash digest as 2 equal length (FS_HALF) parts (LH, RH).
 *  Together (LH,RH,data) is curr_digest.
 *  Iteratively Hash (RH,data) to get next Hash digest (LH,RH).
 *  Concatenate LH from all iterations to combined digest, until getting at least required digest_len bytes.
 *  Initialize first RH to given state, and final RH returned at state - which allows for future calls on same data, getting new digests by continuing the final state.
 */

static void fiat_shamir_bytes_from_state(uint8_t *digest, uint64_t digest_len, const uint8_t *data, uint64_t data_len, uint8_t state[FS_HALF])
{ 
  // Initialize RH to state, so the first hash will operate on (state, data).
  uint8_t *curr_digest = malloc(2*FS_HALF + data_len);
  memcpy(curr_digest + FS_HALF, state, FS_HALF);
  memcpy(curr_digest + 2*FS_HALF, data, data_len);

  uint64_t add_curr_digest_bytes;

  // Continue until remaining needed digest length is 0
  while (digest_len > 0)
  {  
    // hash previous (RH,data) to get new (LH, RH)
    SHA512(curr_digest + FS_HALF, FS_HALF + data_len, curr_digest);

    add_curr_digest_bytes = (digest_len < FS_HALF ? digest_len : FS_HALF);
    
    // collect current LH to final digest
    memcpy(digest, curr_digest, add_curr_digest_bytes);
    
    digest += add_curr_digest_bytes;
    digest_len -= add_curr_digest_bytes;
  }

  // Keep last RH as state for future calls on same data
  memcpy(state, curr_digest + FS_HALF, FS_HALF);
  memset(curr_digest, 0, 2*FS_HALF + data_len);
  free(curr_digest);
}

void fiat_shamir_bytes(uint8_t *digest, uint64_t digest_len, const uint8_t *data, uint64_t data_len)
{
  // Start from default (agreed upon) state of all zeros
  uint8_t fs_state[FS_HALF] = {0};
  fiat_shamir_bytes_from_state(digest, digest_len, data, data_len, fs_state);
  memset(fs_state, 0, FS_HALF);
}

/** 
 *  Get num_res scalars from fiat-shamir on data.
 *  Rejection sampling each scalar until fits in given range (to get pseudo-uniform values)
 */

void fiat_shamir_scalars_in_range(scalar_t *results, uint64_t num_res, const scalar_t range, const uint8_t *data, uint64_t data_len)
{
  uint64_t num_bits = BN_num_bits(range);
  uint64_t num_bytes = BN_num_bytes(range);

  // Start from default (agreed upon) state of all zeros
  uint8_t fs_state[FS_HALF] = {0};
  uint8_t *result_bytes = calloc(num_bytes, 1);

  for (uint64_t i_res = 0; i_res < num_res; ++i_res)
  {
    BN_copy(results[i_res], range);
    
    // Get fiat_shamir scalar (from bytes) which fits in range.
    // If doesn't, get next "fresh" scalar continuing from last state.
    while (BN_cmp(results[i_res], range) != -1)
    {
      fiat_shamir_bytes_from_state(result_bytes, num_bytes, data, data_len, fs_state);
      BN_bin2bn(result_bytes, num_bytes, results[i_res]);
      // Truncate irrelevant bits (w/o biasing distribution)
      BN_mask_bits(results[i_res], num_bits);
    }
  }

  memset(fs_state, 0, FS_HALF);
  free(result_bytes);
}

/**
 *  Auxiliary Information Handling
 */

zkp_aux_info_t *zkp_aux_info_new (uint64_t init_byte_len, const void *init_bytes)
{
  zkp_aux_info_t *aux = malloc(sizeof(*aux));
  
  aux->info = calloc(init_byte_len, 1);
  aux->info_len = init_byte_len;

  if (init_bytes) memcpy(aux->info, init_bytes, init_byte_len);

  return aux;
}

void zkp_aux_info_update(zkp_aux_info_t *aux, uint64_t at_pos, const void *update_bytes, uint64_t update_byte_len)
{
  uint64_t new_len = at_pos + update_byte_len;
  
  // Extend to new length, set with zeros
  if (new_len > aux->info_len)
  {
    aux->info = realloc(aux->info, new_len);
    memset(aux->info + aux->info_len, 0x00, new_len - aux->info_len);
    aux->info_len = new_len;
  }

  if (update_bytes)
  {
    memcpy(aux->info + at_pos, update_bytes, update_byte_len);
  }
  else
  {
    // If no bytes to update, extend/truncate to new length (zero already set above if extended).
    aux->info = realloc(aux->info, new_len);
    aux->info_len = new_len;
  }
}

void zkp_aux_info_update_move(zkp_aux_info_t *aux, uint64_t *at_pos, const void *update_bytes, uint64_t update_byte_len)
{
  zkp_aux_info_update(aux, *at_pos, update_bytes, update_byte_len);
  if (update_bytes) *at_pos += update_byte_len;
}

void zkp_aux_info_free(zkp_aux_info_t *aux)
{
  if (!aux) return;
  
  free(aux->info);
  free(aux);
}