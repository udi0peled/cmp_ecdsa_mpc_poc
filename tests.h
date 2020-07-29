/**
 * 
 *  Name:
 *  tests
 *  
 *  Description:
 *  Test all primitives and the CMP protocol itself
 * 
 *  Usage:
 *  For testing the protocol, number of parties is currently hardcoded as NUM_PARTIES.
 * 
 */

#include "common.h"
#include "primitives.h"

#include <string.h>
#include <assert.h>

#ifndef __CMP20_ECDSA_MPC_TESTS_H__
#define __CMP20_ECDSA_MPC_TESTS_H__

void test_paillier_operations(const paillier_private_key_t *priv);
void test_ring_pedersen(const scalar_t p, const scalar_t q);
void test_fiat_shamir();
void test_scalars(const scalar_t range, uint64_t range_byte_len);
void test_group_elements();
void test_zkp_schnorr();
void test_zkp_encryption_in_range(paillier_public_key_t *paillier_pub, ring_pedersen_public_t *rped_pub);

void test_protocol(uint64_t party_index, uint64_t num_parties, int print_values);

#endif