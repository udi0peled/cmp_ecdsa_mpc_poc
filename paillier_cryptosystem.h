#include <stdint.h>
#include <openssl/bn.h>

#include "algebraic_elements.h"

#ifndef __CMP20_ECDSA_MPC_PAILLIER_CRYPTOSYSTEM_H__
#define __CMP20_ECDSA_MPC_PAILLIER_CRYPTOSYSTEM_H__

#define PAILLIER_MODULUS_BYTES (4*GROUP_ORDER_BYTES)

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
  scalar_t mu;                  // multiplicative factor in decryption
} paillier_private_key_t;


paillier_private_key_t *
      paillier_encryption_generate_key      ();
paillier_public_key_t *
      paillier_encryption_copy_public       (const paillier_private_key_t *priv);
void  paillier_encryption_free_keys         (paillier_private_key_t *priv, paillier_public_key_t *pub);
void  paillier_encryption_sample            (scalar_t rho, const paillier_public_key_t *pub);
void  paillier_encryption_encrypt           (scalar_t ciphertext, const scalar_t plaintext, const scalar_t rho, const paillier_public_key_t *pub);
void  paillier_encryption_decrypt           (scalar_t plaintext, const scalar_t ciphertext, const paillier_private_key_t *priv);
void  paillier_encryption_homomorphic       (scalar_t new_cipher, const scalar_t ciphertext, const scalar_t factor, const scalar_t add_cipher, const paillier_public_key_t *pub);       // factor == NULL, assume 1. add_cipher == NULL, assume 0

#endif