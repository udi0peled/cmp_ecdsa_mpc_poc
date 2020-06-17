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

typedef struct 
{
  scalar_t N;
  scalar_t N2;
} paillier_public_key_t;

typedef struct 
{
  paillier_public_key_t pub;

  scalar_t p;
  scalar_t q;
  scalar_t phi_N;              // exponent in decryption
  scalar_t mu;                 // multiplicative factor in decryption
} paillier_private_key_t;


paillier_private_key_t *paillier_encryption_generate_key  (uint64_t prime_bits);
paillier_private_key_t *paillier_encryption_duplicate_key (const paillier_private_key_t *priv);
paillier_public_key_t  *paillier_encryption_copy_public   (const paillier_private_key_t *priv);
// Free keys, each can be NULL and ignored. Public inside private is freed with private, shouldn't be freeed seperately
void                    paillier_encryption_free_keys     (paillier_private_key_t *priv, paillier_public_key_t *pub);
// Sample randomness to be used in encryption
void                    paillier_encryption_sample        (scalar_t rho, const paillier_public_key_t *pub);
void                    paillier_encryption_encrypt       (scalar_t ciphertext, const scalar_t plaintext, const scalar_t rho, const paillier_public_key_t *pub);
// Doesn't check cipher text is coprime to paillier modulus
void                    paillier_encryption_decrypt       (scalar_t plaintext, const scalar_t ciphertext, const paillier_private_key_t *priv);
// Computed ciphertext*factor + add_cipher (with paillier homomorphic operations). factor==NULL used as 1. add_cipher==NULL, assume as 0.
void                    paillier_encryption_homomorphic   (scalar_t new_cipher, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, const paillier_public_key_t *pub);       

#endif