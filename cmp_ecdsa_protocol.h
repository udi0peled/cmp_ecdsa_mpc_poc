/**
 * 
 *  Name:
 *  cmp_ecdsa_protocol
 *  
 *  Description:
 * 
 *  Proof of concept for the CMP protocol.
 *  Phasese: key generation, refresh and presigning.
 *  Signing is done by non-interactively releasing the signature share for a given message.
 * 
 *  Structure cmp_party_t contains long term data for a party in the protocol.
 *  This data is populated and set by executing the protocol's phases, and specifically ONLY when finalizing a protocol phase, the party's data is updated.
 *  If an error occurs (namely failed verification of zkp or some other check), the protocol should stop and handle it (by halting, retrying or some attack detection). 
 *  However for this POC an error is just printed to screen and the protocol continues (which will probably cause failures later).
 * 
 *  In order to simulate "communication" between parties, but avoiding opening communication channels we chose the following solution:
 *  An array of all other parties' data is kept by each party (by **parties parameter in cmp_party_new).
 *  This way party i can access the data it should have received from party j (at some previous point in time), by accessing directly party j's data.
 *  This of course also allows to access party j's secret data (and data it sent to party k also), which is unwanted in real execution, but for this POC we don't care.
 *  In a real protocol this array of other parties will contain only specific data which was sent (or broadcasted) to the single local party i running on the machine.
 * 
 *  Usage:
 * 
 *  First initializing all parties in some order which is fixed and known to all parties (index sets the order).
 *  Then the following phases should be executed: key_generation and refresh_aux_info.
 *  Now each execution of presigning allows for a single signature_share execution to share a single message.
 *  Calling refresh_aux_info multiple times is also allows, but it deems the presigned data useless (can't be used to signature_share).
 * 
 *  In normal execution, each phase should follow the following function calls:
 *  cmp_<phase>_init:
 *    Constructs the phase relevant information. 
 *  cmp_<phase>_round_<num>_exec:
 *    Execute phase round in order of num (skipping step can cause failure, repeating is possible, but useless).
 *    During rounds only temporary phase's info is updated, not the party's data.
 *  cmp_<phase>_final_exec:
 *    Finish processing phase's temporary data, and update the party's long term data accordingly.
 *  cmp_<phase>_clean:
 *    Cleans and frees all temporary phase's information (not party's data).
 * 
 *  We stress again that since there's no failure handling, even after some failure occured, all rounds will continue to execute and also the party's data can be updated.
 *  This is of course an insecure and unwanted behaviour, which should be changed in a production environment.
 * 
 */

#ifndef __CMP20_ECDSA_MPC_PROTOCOL_H__
#define __CMP20_ECDSA_MPC_PROTOCOL_H__

#include "primitives.h"

// Random Oracle input and output size (SHA512).
#define KAPPA_RANDOM_ORACLE_BYTES 64

typedef uint8_t hash_chunk[KAPPA_RANDOM_ORACLE_BYTES];

/**
 *  Temporary data for key generation phase
 */

typedef struct 
{
  // private/public key pair
  scalar_t  secret_x;
  gr_elem_t public_X;

  // ZKP data
  zkp_aux_info_t  *aux;
  scalar_t        tau;
  zkp_schnorr_t   *psi;             
  // Schnorr zkp commitment from all other parties
  scalar_t        *received_A;      

  // Echo broadcast and random oracle data seed
  hash_chunk srid;
  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_broadcast;

  // all other party's public keys
  scalar_t *received_X;

  uint64_t run_time;
} cmp_key_generation_t;


/**
 *  Temporary data for refresh auxiliary infromation phase
 */

typedef struct 
{
  // Generated paillier and ring pedersen keys
  paillier_private_key_t  *paillier_priv;
  ring_pedersen_private_t *rped_priv;

  // Resharing the same secret, and paillier commitments of shares
  scalar_t  *reshare_secret_x_j;
  scalar_t  *encrypted_reshare_j;
  gr_elem_t *reshare_public_X_j;
  
  // ZKP data
  zkp_aux_info_t              *aux;
  scalar_t                    *tau;
  zkp_schnorr_t               **psi_sch;
  zkp_paillier_blum_modulus_t *psi_mod;
  zkp_ring_pedersen_param_t   *psi_rped;

  // Echo broadcast and random oracle data seed
  hash_chunk rho;
  hash_chunk combined_rho;
  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_broadcast;

  uint64_t prime_time;
  uint64_t run_time;
} cmp_refresh_aux_info_t;

/**
 *  Temporary data for presigning phase
 */

typedef struct 
{
  scalar_t G;
  scalar_t K;
  scalar_t k;
  scalar_t rho;
  scalar_t nu;
  scalar_t gamma;
  scalar_t delta;
  scalar_t chi;

  scalar_t *alpha_j;
  scalar_t *beta_j;
  scalar_t *alphahat_j;
  scalar_t *betahat_j;
  scalar_t *D_j;
  scalar_t *F_j;
  scalar_t *Dhat_j;
  scalar_t *Fhat_j;

  gr_elem_t Delta;
  gr_elem_t Gamma;
  gr_elem_t combined_Gamma;

  zkp_aux_info_t                            *aux;
  zkp_encryption_in_range_t                 **psi_enc;
  zkp_operation_paillier_commitment_range_t **psi_affp;
  zkp_operation_group_commitment_range_t    **psi_affg;
  zkp_group_vs_paillier_range_t             **psi_logG;
  zkp_group_vs_paillier_range_t             **psi_logK;

  hash_chunk echo_broadcast;

  uint64_t run_time;
} cmp_presigning_t;

/**
 *  Long term data for party.
 *  Updated only when finalizing a phase.
 */

typedef struct cmp_party_t
{
  uint64_t id;
  // Party's index in parties array, important to be consisten betwenn all parties
  uint64_t index;
  uint64_t num_parties;
  uint64_t *parties_ids;

  // Private key, and all parties public keys (by index)
  scalar_t  secret_x;
  gr_elem_t *public_X;

  // My private key and all parties's public keys (by party index)
  paillier_private_key_t *paillier_priv;
  paillier_public_key_t  **paillier_pub;   
  ring_pedersen_public_t **rped_pub;

  ec_group_t ec;
  gr_elem_t ec_gen;
  scalar_t ec_order;

  // Session's id and hash seed
  hash_chunk sid;
  hash_chunk srid;
  hash_chunk sid_hash;

  // Temporary data for relevant phase
  cmp_key_generation_t    *key_generation_data;
  cmp_refresh_aux_info_t  *refresh_data;
  cmp_presigning_t        *presigning_data;

  // Generated signature share
  gr_elem_t R;
  scalar_t k;
  scalar_t chi;

  // Access all other parties' data (and temporary data when relevant), instead of communication
  struct cmp_party_t **parties;             
} cmp_party_t;

void cmp_party_new  (cmp_party_t **parties, uint64_t num_parties, const uint64_t *parties_ids, uint64_t index, const hash_chunk sid);
void cmp_party_free (cmp_party_t *party);

void cmp_key_generation_init         (cmp_party_t *party);
void cmp_key_generation_clean        (cmp_party_t *party);
void cmp_key_generation_round_1_exec (cmp_party_t *party);
void cmp_key_generation_round_2_exec (cmp_party_t *party);
void cmp_key_generation_round_3_exec (cmp_party_t *party);
void cmp_key_generation_final_exec   (cmp_party_t *party);

void cmp_refresh_aux_info_init         (cmp_party_t *party);
void cmp_refresh_aux_info_clean        (cmp_party_t *party);
void cmp_refresh_aux_info_round_1_exec (cmp_party_t *party);
void cmp_refresh_aux_info_round_2_exec (cmp_party_t *party);
void cmp_refresh_aux_info_round_3_exec (cmp_party_t *party);
void cmp_refresh_aux_info_final_exec   (cmp_party_t *party);

void cmp_presigning_init         (cmp_party_t *party);
void cmp_presigning_clean        (cmp_party_t *party);
void cmp_presigning_round_1_exec (cmp_party_t *party);
void cmp_presigning_round_2_exec (cmp_party_t *party);
void cmp_presigning_round_3_exec (cmp_party_t *party);
void cmp_presigning_final_exec   (cmp_party_t *party);

void cmp_signature_share (scalar_t r, scalar_t sigma, const cmp_party_t *party, const scalar_t msg);

void cmp_comm_send_bytes(uint64_t my_index, uint64_t to_index, uint64_t round, const uint8_t *bytes, uint64_t byte_len);
void cmp_comm_receive_bytes(uint64_t my_index, uint64_t to_index, uint64_t round, uint8_t *bytes, uint64_t byte_len);

#endif