/**
 * 
 *  Name:
 *  cmp_protocol
 *  
 *  Description:
 * 
 *  Proof of concept for the CMP protocol.
 *  Phasese: key generation, refresh and presign.
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
 *  Now each execution of presign allows for a single signature_share execution to share a single message.
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

// Random Oracle input and output byte size (SHA512).
typedef uint8_t hash_chunk[64];


/****************************** 
 * 
 *    Key Generation Phase
 * 
 ******************************/

// Payload received from other parties
typedef struct 
{
  // Public key share
  gr_elem_t public_X;

  // Schnorr ZKP 
  gr_elem_t           commited_A;
  zkp_schnorr_proof_t *psi_sch;

  // Echo broadcast and random oracle data seed
  hash_chunk srid;
  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_broadcast;

} cmp_key_generation_payload_t;

// Data generated, and payload received from others (including sent payload)
typedef struct 
{
  // Private.Pוublic key share
  scalar_t  secret_x;
  gr_elem_t public_X;

  // ZKP Schnorr
  scalar_t            tau;
  gr_elem_t           commited_A;
  zkp_schnorr_proof_t *psi_sch;

  // Echo broadcast and random oracle data seed
  uint8_t *srid;
  uint8_t *u;
  uint8_t *V;
  uint8_t *echo_broadcast;

  // Recevied KGD payload of all parties (including self to send)
  cmp_key_generation_payload_t **payload;

  uint64_t run_time;

} cmp_key_generation_data_t;


/************************************************** 
 * 
 *   Key and Auxiliary Information Refresh Phase
 * 
 **************************************************/

// Payloads received from each party during phase
typedef struct 
{
  // Generated paillier and ring pedersen keys
  paillier_public_key_t  *paillier_pub;
  ring_pedersen_public_t *rped_pub;

  // Resharing the same secret, and paillier commitments of shares
  scalar_t  *encrypted_reshare_k;
  gr_elem_t *reshare_public_X_k;
  
  // ZKP data
  gr_elem_t                         *commited_A_k;
  zkp_schnorr_proof_t               **psi_sch_k;
  zkp_paillier_blum_modulus_proof_t *psi_mod;
  zkp_ring_pedersen_param_proof_t   *psi_rped;

  // Echo broadcast and random oracle data seed
  hash_chunk rho;
  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_broadcast;

} cmp_refresh_payload_t;

// Data generated (and partially sent) by party during phase

typedef struct 
{
  // Paillier and ring pedersen keys
  paillier_private_key_t  *paillier_priv;
  paillier_public_key_t   *paillier_pub;
  ring_pedersen_private_t *rped_priv;
  ring_pedersen_public_t  *rped_pub;

  // Resharing the same secret, and paillier commitments of shares
  scalar_t  *reshare_secret_x_j;
  scalar_t  *encrypted_reshare_j;
  gr_elem_t *reshare_public_X_j;
  
  // All ZKP
  scalar_t                          *tau_j;
  gr_elem_t                         *commited_A_j;
  zkp_schnorr_proof_t               **psi_sch_j;
  zkp_paillier_blum_modulus_proof_t *psi_mod;
  zkp_ring_pedersen_param_proof_t   *psi_rped;

  // Echo broadcast and random oracle data seed
  hash_chunk combined_rho;
  uint8_t *rho;
  uint8_t *u;
  uint8_t *V;
  uint8_t *echo_broadcast;

  // Payload from other parties 
  cmp_refresh_payload_t **payload;

  uint64_t prime_time;
  uint64_t run_time;

} cmp_refresh_data_t;

/**
 *  Temporary data for ecdsa presign phase
 */

typedef struct 
{
  scalar_t  G;
  scalar_t  K;
  scalar_t  D;
  scalar_t  F;
  scalar_t  Dhat;
  scalar_t  Fhat;
  scalar_t  delta;
  gr_elem_t Delta;
  gr_elem_t Gamma;

  zkp_encryption_in_range_proof_t        *psi_enc;
  zkp_oper_paillier_commit_range_proof_t *psi_affp;
  zkp_oper_group_commit_range_proof_t    *psi_affg;
  zkp_group_vs_paillier_range_proof_t    *psi_logG;
  zkp_group_vs_paillier_range_proof_t    *psi_logK;

  hash_chunk echo_broadcast;

  uint64_t run_time;
} cmp_ecdsa_presign_payload_t;


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

  //scalar_t *alpha_j;
  scalar_t *beta_j;
  //scalar_t *alphahat_j;
  scalar_t *betahat_j;
  scalar_t *D_j;
  scalar_t *F_j;
  scalar_t *Dhat_j;
  scalar_t *Fhat_j;

  gr_elem_t Delta;
  gr_elem_t Gamma;
  gr_elem_t combined_Gamma;

  zkp_encryption_in_range_proof_t        **psi_enc_j;
  zkp_oper_paillier_commit_range_proof_t **psi_affp_j;
  zkp_oper_group_commit_range_proof_t    **psi_affg_j;
  zkp_group_vs_paillier_range_proof_t    **psi_logG_j;
  zkp_group_vs_paillier_range_proof_t    **psi_logK_j;

  uint8_t *echo_broadcast;

  cmp_ecdsa_presign_payload_t **payload;

  uint64_t run_time;
} cmp_ecdsa_presign_data_t;


/**
 *  Temporary data for ecdsa signing phase
 */

typedef struct
{
  scalar_t sigma;
} cmp_signing_payload_t;

typedef struct
{
  cmp_signing_payload_t **payload;
  scalar_t sigma;
  scalar_t r;
} cmp_ecdsa_signing_data_t;


/**
 *  Temporary data for schnorr presign phase
 */

typedef struct 
{
  scalar_t  K;
  gr_elem_t R;

  zkp_encryption_in_range_proof_t     *psi_enc;
  zkp_group_vs_paillier_range_proof_t *psi_logK;

  hash_chunk echo_broadcast; 
} cmp_schnorr_presign_payload_t;


typedef struct 
{
  scalar_t  k;
  scalar_t  rho;
  scalar_t  K;
  gr_elem_t R;

  zkp_encryption_in_range_proof_t     **psi_enc_j;
  zkp_group_vs_paillier_range_proof_t **psi_logK_j;

  uint8_t *echo_broadcast;

  cmp_schnorr_presign_payload_t **payload;
} cmp_schnorr_presign_data_t;

/**
 *  Temporary data for schnorr signing phase
 */

typedef struct
{
  scalar_t sigma;
} cmp_schnorr_signing_payload_t;

typedef struct
{
  cmp_signing_payload_t **payload;
  scalar_t sigma;
  scalar_t r;
} cmp_schnorr_signing_data_t;


/**
 *  Long term data for party.
 *  Updated only when finalizing a phase.
 */

typedef struct cmp_party_t
{
  // Party's index in parties array, important to be consisten betwenn all parties
  uint64_t index;
  uint64_t id;
  uint64_t num_parties;
  uint64_t *parties_ids;

  // Private key, and all parties public keys (by index)
  scalar_t  secret_x;
  gr_elem_t *public_X;

  // My private key and all parties's public keys (by index)
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
  cmp_key_generation_data_t  *key_generation_data;
  cmp_refresh_data_t         *refresh_data;
  cmp_ecdsa_presign_data_t   *ecdsa_presign_data;
  cmp_ecdsa_signing_data_t   *ecdsa_signing_data;
  cmp_schnorr_presign_data_t *schnorr_presign_data;
  cmp_schnorr_signing_data_t *schnorr_signing_data;

  // Generated signature share
  gr_elem_t R;
  scalar_t k;
  scalar_t chi;

  // Access all other parties' data (and temporary data when relevant), instead of communication
  struct cmp_party_t **parties;
} cmp_party_t;

cmp_party_t *cmp_party_new  (uint64_t party_index, uint64_t num_parties, const uint64_t *parties_ids, const hash_chunk sid);
void         cmp_party_free (cmp_party_t *party);

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

// ECDSA Signature

void cmp_ecdsa_presign_init         (cmp_party_t *party);
void cmp_ecdsa_presign_clean        (cmp_party_t *party);
void cmp_ecdsa_presign_round_1_exec (cmp_party_t *party);
void cmp_ecdsa_presign_round_2_exec (cmp_party_t *party);
void cmp_ecdsa_presign_round_3_exec (cmp_party_t *party);
void cmp_ecdsa_presign_final_exec   (cmp_party_t *party);

void cmp_ecdsa_signing_init         (cmp_party_t *party);
void cmp_ecdsa_signing_clean        (cmp_party_t *party);
void cmp_ecdsa_signing_round_1_exec (const cmp_party_t *party, const scalar_t msg);
void cmp_ecdsa_signing_final_exec   (scalar_t r, scalar_t s, const cmp_party_t *party);

// Schnorr Signature (EdDSA)

void cmp_schnorr_presign_init         (cmp_party_t *party);
void cmp_schnorr_presign_clean        (cmp_party_t *party);
void cmp_schnorr_presign_round_1_exec (cmp_party_t *party);
void cmp_schnorr_presign_round_2_exec (cmp_party_t *party);
void cmp_schnorr_presign_final_exec   (cmp_party_t *party);

void cmp_schnorr_signing_init         (cmp_party_t *party);
void cmp_schnorr_signing_clean        (cmp_party_t *party);
void cmp_schnorr_signing_round_1_exec (const cmp_party_t *party, const scalar_t msg);
void cmp_schnorr_signing_final_exec   (scalar_t r, scalar_t s, const cmp_party_t *party);

void cmp_comm_send_bytes(uint64_t my_index, uint64_t to_index, uint64_t round, const uint8_t *bytes, uint64_t byte_len);
void cmp_comm_receive_bytes(uint64_t my_index, uint64_t to_index, uint64_t round, uint8_t *bytes, uint64_t byte_len);

#endif