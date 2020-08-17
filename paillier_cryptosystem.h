/**
 * 
 *  Name:
 *  paillier_cryptosystem
 *  
 *  Description:
 *  Basic paillier cryptosystem: private/public key, encrypt/decrypt and (additive) homomorphic operation.
 * 
 *  Usage:
 *  Generate private key of wanted (prime) bit size, public key can be extracted from it.
 *  Plaintext and ciphertexts are scalars in the relevant modulus rings (N, N^2).
 *  To encrypt, need to sample randomness frst to be used in encrpytion.
 * 
 */

#ifndef __CMP20_ECDSA_MPC_PAILLIER_CRYPTOSYSTEM_H__
#define __CMP20_ECDSA_MPC_PAILLIER_CRYPTOSYSTEM_H__

#include "algebraic_elements.h"
#include <assert.h>

typedef struct 
{
  scalar_t N;
  scalar_t N2;
} paillier_public_key_t;

typedef struct 
{
  // Public
  scalar_t N;
  scalar_t N2;

  // Private
  scalar_t p;
  scalar_t q;
  scalar_t phi_N;              // exponent in decryption
  scalar_t mu;                 // multiplicative factor in decryption
} paillier_private_key_t;


paillier_private_key_t *
     paillier_encryption_private_new      ();
paillier_public_key_t *
     paillier_encryption_public_new       ();
void paillier_encryption_generate_private (paillier_private_key_t *priv, uint64_t prime_bits);
// If pub==NULL and priv!=NULL, copy_pub from priv
void paillier_encryption_copy_keys        (paillier_private_key_t *copy_priv, paillier_public_key_t *copy_pub, const paillier_private_key_t *priv, const paillier_public_key_t *pub);
// Free keys, each can be NULL and ignored. Public inside private is freed with private, shouldn't be freeed seperately
void paillier_encryption_free_keys        (paillier_private_key_t *priv, paillier_public_key_t *pub);
// Sample randomness to be used in encryption
void paillier_encryption_sample           (scalar_t rho, const paillier_public_key_t *pub);
void paillier_encryption_encrypt          (scalar_t ciphertext, const scalar_t plaintext, const scalar_t rho, const paillier_public_key_t *pub);
// Doesn't check cipher text is coprime to paillier modulus
void paillier_encryption_decrypt          (scalar_t plaintext, const scalar_t ciphertext, const paillier_private_key_t *priv);
// Computed ciphertext*factor + add_cipher (with paillier homomorphic operations). factor==NULL used as 1. add_cipher==NULL, assume as 0.
void paillier_encryption_homomorphic      (scalar_t new_cipher, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, const paillier_public_key_t *pub);       
void paillier_public_to_bytes             (uint8_t **bytes, uint64_t *byte_len, const paillier_public_key_t *pub, uint64_t paillier_modulus_bytes, int move_to_end);
void paillier_public_from_bytes           (paillier_public_key_t *pub, uint8_t **bytes, uint64_t *byte_len, uint64_t paillier_modulus_bytes, int move_to_end);

#endif