#include <openssl/rand.h>
#include "tests.h"
#include "cmp_ecdsa_protocol.h"

void test_scalars(const scalar_t range, uint64_t range_byte_len)
{
  printf("# test_scalars\n");

  scalar_t alpha = scalar_new();
  scalar_t beta = scalar_new();
  scalar_t gamma = scalar_new();

  scalar_sample_in_range(alpha, range, 0);
  scalar_sample_in_range(beta, range, 1);

  printBIGNUM("range = ", range, " ");
  printf("#(%d bytes, should be %lu)\n", BN_num_bytes(range), range_byte_len);

  printBIGNUM("alpha = ", alpha, " ");
  printf("#(%d bytes)\n", BN_num_bytes(alpha));

  printBIGNUM("beta = ", beta, " ");
  printf("#(%d bytes)\n", BN_num_bytes(beta));

  uint8_t *alpha_bytes = malloc(range_byte_len);
  scalar_to_bytes(&alpha_bytes, range_byte_len, alpha, 0);
  printHexBytes("alpha_bytes = 0x", alpha_bytes, range_byte_len, "\n", 1);

  scalar_make_signed(alpha, range);
  printBIGNUM("alpha_s = ", alpha, "\n");
  
  scalar_exp(gamma, beta, alpha, range);
  printBIGNUM("# beta ** alpha_s (mod range) = ", gamma, "\n");

  scalar_add(gamma, beta, alpha, range);
  printBIGNUM("# ", gamma, " ==\n");
  printf("(beta + alpha_s) %% range\n");

  scalar_mul(gamma, beta, alpha, range);
  printBIGNUM("# ", gamma, "  ==\n");
  printf("(beta * alpha_s) %% range\n");

  scalar_inv(gamma, alpha, range);
  printBIGNUM("# ", gamma, " ==\n");
  printf("mod_inverse(alpha_s,range)\n");


  free(alpha_bytes);
  scalar_free(gamma);
  scalar_free(alpha);
  scalar_free(beta);
}

void test_group_elements()
{
  printf("# test_group_elements\n");
  printf("import secp256k1\n");

  ec_group_t ec = ec_group_new();
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t exps[2];
  exps[0] = scalar_new();
  exps[1] = scalar_new();
  scalar_sample_in_range(exps[0], ec_group_order(ec), 0);
  scalar_sample_in_range(exps[1], ec_group_order(ec), 0);
  printBIGNUM("exps = [", exps[0], ",");
  printBIGNUM("", exps[1], "]\n");

  gr_elem_t el[3];
  el[0] = group_elem_new(ec);
  el[1] = group_elem_new(ec);
  el[2] = group_elem_new(ec);
  printf("el = [0, 1, 2]\n");

  group_operation(el[0], NULL, (const gr_elem_t) ec_group_generator(ec), exps[0], ec);
  
  gr_elem_t p = el[0];
  uint64_t p_byte_len = EC_POINT_point2oct(ec, p, (POINT_CONVERSION_COMPRESSED), NULL, 0, bn_ctx);
  uint8_t *p_bytes = calloc(p_byte_len, 1);
  printf("point2oct = %ld, p_bytes = %lu\n",
  EC_POINT_point2oct(ec, p, ( POINT_CONVERSION_COMPRESSED), p_bytes, p_byte_len, bn_ctx),
  p_byte_len);
  printHexBytes("p_bytes = ", p_bytes, p_byte_len, "\n", 1);
  
  gr_elem_t q = group_elem_new(ec);
  group_operation(q, NULL, NULL, NULL, ec);
  printECPOINT("# q = ", q, ec, "\n", 0);

  printHexBytes("p_bytes = ", p_bytes, p_byte_len, "\n", 1);
  printf("oct2point %d\n",  EC_POINT_oct2point(ec, q, p_bytes, p_byte_len, bn_ctx));
  printECPOINT("# q = ", q, ec, "\n", 0);

  group_operation(q, NULL, NULL, NULL, ec);
  memset(p_bytes, 0x01, 1);
  printHexBytes("p_bytes = ", p_bytes, p_byte_len, "\n", 1);
  printf("oct2point %d\n",  EC_POINT_oct2point(ec, q, p_bytes, p_byte_len, bn_ctx));
  printECPOINT("# q = ", q, ec, "\n", 0);

  group_elem_free(q);

  
  printECPOINT("# el[0] = ", el[0], ec, "\n", 0);
  printf("el[0] = G * exps[0]\n");

  group_operation(el[1], NULL, (const gr_elem_t) ec_group_generator(ec), exps[1], ec);  
  printECPOINT("# el[1] = ", el[1], ec, "\n", 0);
  printf("el[1] = G * exps[1]\n");
  
  group_operation(el[2], el[0], el[1],(const scalar_t) BN_value_one(), ec);
  printECPOINT("# results = ", el[2], ec, "\n", 0);
  printf("el[0] + el[1]\n");

  group_operation(el[2], el[0], el[1], exps[0], ec);
  printECPOINT("# results = ", el[2], ec, "\n", 0);
  printf("el[0] + el[1]**exps[0]\n");

  scalar_free(exps[0]);
  scalar_free(exps[1]);
  group_elem_free(el[0]);
  group_elem_free(el[1]);
  group_elem_free(el[2]);
  BN_CTX_free(bn_ctx);
  ec_group_free(ec);
}

void test_paillier_operations(const paillier_private_key_t *priv) 
{
  printf("# test_paillier_operations\n");

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t plaintext = scalar_new();
  scalar_t randomness = scalar_new();
  scalar_t ciphertext = scalar_new();
  scalar_t decrypted = scalar_new();

  paillier_public_key_t *pub = paillier_encryption_public_new();
  paillier_encryption_copy_keys(NULL, pub, priv, NULL);
  
  scalar_sample_in_range(plaintext, pub->N , 0);
  printBIGNUM("plaintext = ", plaintext, "\n");

  paillier_encryption_sample(randomness, pub);
  printBIGNUM("randomness = ", (randomness), "\n");

  paillier_encryption_encrypt(ciphertext, plaintext, randomness, pub);
  printBIGNUM("ciphertext = ", (ciphertext), "\n");

  paillier_encryption_decrypt(decrypted, ciphertext, priv);
  printBIGNUM("decrypted = ", (decrypted), "\n");

  assert(BN_cmp(plaintext, decrypted) == 0);

  paillier_encryption_homomorphic(ciphertext, ciphertext, plaintext, ciphertext, pub);
  printBIGNUM("ciphertext = ", (ciphertext), "\n");

  paillier_encryption_decrypt(decrypted, ciphertext, priv);
  printBIGNUM("decrypted = ", (decrypted), "\n");

  BN_mod_mul(randomness, plaintext, plaintext, pub->N, bn_ctx);
  BN_mod_add(randomness, randomness, plaintext, pub->N, bn_ctx);
  printBIGNUM("expected  = ", (randomness), "\n");

  assert(BN_cmp(randomness, decrypted) == 0);

  paillier_encryption_free_keys(NULL, pub);
  scalar_free(plaintext);
  scalar_free(randomness);
  scalar_free(ciphertext);
  scalar_free(decrypted);
  BN_CTX_free(bn_ctx);
}

void test_ring_pedersen(const scalar_t p, const scalar_t q) 
{
  printf("# test_ring_pedersen\n");

  ring_pedersen_private_t *rped_priv = ring_pedersen_private_new();
  ring_pedersen_public_t *rped_pub = ring_pedersen_public_new();
  ring_pedersen_private_from_primes(rped_priv, p, q);
  ring_pedersen_copy_param(NULL, rped_pub, rped_priv, NULL);

  printBIGNUM("N = ", (rped_pub->N), "\n");
  printBIGNUM("s = ", (rped_pub->s), "\n");
  printBIGNUM("t = ", (rped_pub->t), "\n");
  printBIGNUM("ped_lam = ", (rped_priv->lam), "\n");
  printBIGNUM("phi_N = ", (rped_priv->phi_N), "\n");

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  scalar_t s_exp = scalar_new();
  scalar_t t_exp = scalar_new();
  scalar_t rped_com = scalar_new();
  
  scalar_sample_in_range(s_exp, rped_pub->N, 0);
  // scalar_make_signed(s_exp, rped_pub->N);
  printBIGNUM("s_exp = ", (s_exp), "\n");

  scalar_sample_in_range(t_exp, rped_pub->N, 0);
  printBIGNUM("t_exp = ", (t_exp), "\n");

  ring_pedersen_commit(rped_com, s_exp, t_exp, rped_pub);
  printBIGNUM("rped_com = ", (rped_com), "\n");

  ring_pedersen_free_param(rped_priv, rped_pub);
  scalar_free(s_exp);
  scalar_free(t_exp);
  scalar_free(rped_com);
  BN_CTX_free(bn_ctx);
}

void test_fiat_shamir(uint64_t digest_len, uint64_t data_len)
{
  uint8_t zeros[32] = {0};
  uint8_t *data = malloc(data_len);
  RAND_bytes(data, data_len);

  printf("# test_fiat_shamir\n");
  printHexBytes("data = ", zeros, sizeof(zeros), "", 1);
  printHexBytes("", data, data_len, "\n", 1);

  uint8_t *digest = malloc(digest_len);
  fiat_shamir_bytes(digest, digest_len, data, data_len);

  printf("digest = ");
  for (uint64_t i = 0; i < digest_len; i += 32)
  {
    printHexBytes("", digest + i, (digest_len - i <  32  ? digest_len - i : 32), " ", 1);
  }
  printf("\n");

  // test scalars in range

  scalar_t range = scalar_new();

  #define NUM_REPS 5
  scalar_t num[NUM_REPS];
  for (uint64_t i = 0; i < NUM_REPS; ++i) { num[i] = scalar_new(); } 

  BN_set_word(range, 53);

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  BN_exp(range, range, range, bn_ctx);

  printBIGNUM("range = ", range, " ");
  printf("#(%d bits = %d bytes)\n", BN_num_bits(range), BN_num_bytes(range));

  fiat_shamir_scalars_in_range(num, NUM_REPS, range, data, data_len);

  printf("num = [0] * %d\n", NUM_REPS);
  for (uint64_t i = 0; i < NUM_REPS; ++i) {
    printf("num[%lu] = ", i);
    printBIGNUM("", num[i], " ");
    printf("#(%d bits = %d bytes)\n", BN_num_bits(num[i]), BN_num_bytes(num[i]));
  }

  scalar_free(range);
  for (uint64_t i = 0; i < NUM_REPS; ++i) { scalar_free(num[i]);} 
  free(data);
  free(digest);
  BN_CTX_free(bn_ctx);
}

void test_zkp_schnorr()
{
  printf("# test_zkp_schnorr\n");
  
  zkp_aux_info_t aux;
  aux.info = NULL;
  aux.info_len = 0;

  zkp_schnorr_public_t zkp_public;
  zkp_public.G = ec_group_new();
  zkp_public.g = ec_group_generator(zkp_public.G);
  zkp_public.X = group_elem_new(zkp_public.G);

  zkp_schnorr_proof_t *zkp_proof = zkp_schnorr_new(zkp_public.G);

  zkp_schnorr_secret_t zkp_secret;
  zkp_secret.x = scalar_new();
  scalar_sample_in_range(zkp_secret.x, ec_group_order(zkp_public.G), 0);

  group_operation(zkp_public.X, NULL, zkp_public.g, zkp_secret.x, zkp_public.G);

  scalar_t alpha = scalar_new();

  zkp_schnorr_commit(zkp_proof->A, alpha, &zkp_public);
  zkp_schnorr_prove(zkp_proof, alpha, &zkp_secret, &zkp_public, &aux);
  printf("# 1 == %d : valid\n", zkp_schnorr_verify(zkp_proof, &zkp_public, &aux));

  BN_add_word(alpha,1);
  zkp_schnorr_prove(zkp_proof, alpha, &zkp_secret, &zkp_public, &aux);
  printf("# 1 == %d : alpha changed\n", zkp_schnorr_verify(zkp_proof, &zkp_public, &aux));

  BN_add_word(zkp_secret.x,1);
  zkp_schnorr_prove(zkp_proof, alpha, &zkp_secret, &zkp_public, &aux);
  printf("# 0 == %d : wrond secret.x\n", zkp_schnorr_verify(zkp_proof, &zkp_public, &aux));

  BN_sub_word(zkp_secret.x,1);
  BN_add_word(zkp_proof->z, 1);
  printf("# 0 == %d : wrong z\n", zkp_schnorr_verify(zkp_proof, &zkp_public, &aux));

  aux.info = malloc(1);
  aux.info_len = 1;
  printf("# 0 == %d : wrong aux\n", zkp_schnorr_verify(zkp_proof, &zkp_public, &aux));
  
  free(aux.info);
  scalar_free(alpha);
  scalar_free(zkp_secret.x);
  
  group_elem_free(zkp_public.X);
  ec_group_free(zkp_public.G);

  zkp_schnorr_free(zkp_proof);
}

void test_zkp_encryption_in_range(paillier_public_key_t *paillier_pub, ring_pedersen_public_t *rped_pub, uint64_t k_range_bytes)
{
  printf("#  test encryption_in_range\n");

  zkp_aux_info_t *aux = zkp_aux_info_new(1, &k_range_bytes); // just some value

  zkp_encryption_in_range_proof_t *proof = zkp_encryption_in_range_new();
  zkp_encryption_in_range_public_t public;
  zkp_encryption_in_range_secret_t secret;
  
  ec_group_t G = ec_group_new();

  public.challenge_modulus = ec_group_order(G);
  public.paillier_pub = paillier_pub;
  public.rped_pub = rped_pub;
  public.K = scalar_new();
  public.k_range_bytes = k_range_bytes;

  secret.k = scalar_new();
  secret.rho = scalar_new();

  scalar_t sample_range = scalar_new();
  scalar_set_power_of_2(sample_range, public.k_range_bytes);
  scalar_sample_in_range(secret.k, sample_range, 0);

  paillier_encryption_sample(secret.rho, paillier_pub);
  paillier_encryption_encrypt(public.K, secret.k, secret.rho, paillier_pub);

  printBIGNUM("k = ", secret.k, "\n");
  printBIGNUM("rho = ", secret.rho, "\n");

  printBIGNUM("N0 = ", public.paillier_pub->N, "\n");
  printBIGNUM("Nhat = ", public.rped_pub->N, "\n");
  printBIGNUM("s = ", public.rped_pub->s, "\n");
  printBIGNUM("t = ", public.rped_pub->t, "\n");
  printBIGNUM("K = ", public.K, "\n");

  zkp_encryption_in_range_prove(proof, &secret, &public, aux);
  printf("# 1 == %d : valid \n", zkp_encryption_in_range_verify(proof, &public, aux));

  BN_add_word(secret.k, 1);
  zkp_encryption_in_range_prove(proof, &secret, &public, aux);
  printf("# 0 == %d : wrong secret.k\n", zkp_encryption_in_range_verify(proof, &public, aux));

  BN_sub_word(secret.k, 1);
  BN_add_word(secret.rho, 1);
  zkp_encryption_in_range_prove(proof, &secret, &public, aux);
  printf("# 0 == %d : wrong secret.rho\n", zkp_encryption_in_range_verify(proof, &public, aux));

  
  scalar_set_power_of_2(sample_range, 8*k_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES );
  scalar_add(secret.k, secret.k, sample_range, public.paillier_pub->N);
  
  paillier_encryption_sample(secret.rho, paillier_pub);
  paillier_encryption_encrypt(public.K, secret.k, secret.rho, paillier_pub);
  zkp_encryption_in_range_prove(proof, &secret, &public, aux);
  printf("# 0 == %d : too big secret\n", zkp_encryption_in_range_verify(proof, &public, aux));

  zkp_aux_info_update(aux, 1, NULL, 1);
  printf("# 0 == %d : wrong aux\n", zkp_encryption_in_range_verify(proof, &public, aux));

  zkp_aux_info_update(aux, 1, NULL, 0);
  
  printf("Testing to/from bytes\n");

  uint64_t zkp_bytelen;
  zkp_encryption_in_range_proof_to_bytes(NULL, &zkp_bytelen, NULL, k_range_bytes, 0);

  uint8_t *zkp_bytes = malloc(zkp_bytelen);
  zkp_encryption_in_range_proof_to_bytes(&zkp_bytes, &zkp_bytelen, proof, k_range_bytes, 0);

  zkp_encryption_in_range_proof_t *proof_enc_copy = zkp_encryption_in_range_new();
  zkp_encryption_in_range_proof_from_bytes(proof_enc_copy, &zkp_bytes, &zkp_bytelen, k_range_bytes, paillier_pub->N, 0);

  printf("same A %d [%d, %d]\n", scalar_equal(proof_enc_copy->A,     proof->A),   BN_num_bits(proof_enc_copy->A),   BN_num_bits(proof->A));
  printf("same C %d [%d, %d]\n", scalar_equal(proof_enc_copy->C,     proof->C),   BN_num_bits(proof_enc_copy->C),   BN_num_bits(proof->C));
  printf("same S %d [%d, %d]\n", scalar_equal(proof_enc_copy->S,     proof->S),   BN_num_bits(proof_enc_copy->S),   BN_num_bits(proof->S));
  printf("same z_1 %d [%d, %d]\n", scalar_equal(proof_enc_copy->z_1, proof->z_1), BN_num_bits(proof_enc_copy->z_1), BN_num_bits(proof->z_1));
  printf("same z_2 %d [%d, %d]\n", scalar_equal(proof_enc_copy->z_2, proof->z_2), BN_num_bits(proof_enc_copy->z_2), BN_num_bits(proof->z_2));
  printf("same z_3 %d [%d, %d]\n", scalar_equal(proof_enc_copy->z_3, proof->z_3), BN_num_bits(proof_enc_copy->z_3), BN_num_bits(proof->z_3));

  zkp_aux_info_free(aux);
  scalar_free(sample_range);
  scalar_free(secret.k);
  scalar_free(secret.rho);
  scalar_free(public.K);
  ec_group_free(G);
  zkp_encryption_in_range_free(proof);
  zkp_encryption_in_range_free(proof_enc_copy);
}

/**
 * 
 *  Protocol Tests
 *
 */

void execute_key_generation (cmp_party_t *party)
{
  // Execute Key Generation for all
  cmp_key_generation_init(party);
  cmp_key_generation_round_1_exec(party);
  cmp_key_generation_round_2_exec(party);
  cmp_key_generation_round_3_exec(party);
  cmp_key_generation_final_exec(party);
  cmp_key_generation_clean(party);
}

void execute_refresh_and_aux_info (cmp_party_t *party)
{
  // Execute Key Generation for all
  cmp_refresh_aux_info_init(party);
  cmp_refresh_aux_info_round_1_exec(party);
  cmp_refresh_aux_info_round_2_exec(party);
  cmp_refresh_aux_info_round_3_exec(party);
  cmp_refresh_aux_info_final_exec(party);
  cmp_refresh_aux_info_clean(party);
}

void get_public_key(gr_elem_t pubkey, cmp_party_t *parties[], uint64_t num_parties)
{
  gr_elem_t *pub = calloc(num_parties, sizeof(gr_elem_t));
  for (uint64_t i = 0; i < num_parties; ++i)
  {
    pub[i] = group_elem_new(parties[i]->ec);
    group_elem_copy(pub[i], parties[i]->public_X[0]);
    for (uint64_t k = 1; k < parties[i]->num_parties; ++k)
    { 
      group_operation(pub[i], pub[i], parties[i]->public_X[k], NULL, parties[i]->ec);  
    }
    assert(group_elem_equal(pub[0], pub[i], parties[0]->ec));
  }
  group_elem_copy(pubkey, pub[0]);

  for (uint64_t i = 0; i < num_parties; ++i) group_elem_free(pub[i]);
  free(pub);
}

void execute_presign (cmp_party_t *party)
{
  cmp_presign_init(party);
  cmp_presign_round_1_exec(party);
  cmp_presign_round_2_exec(party);
  cmp_presign_round_3_exec(party);
  cmp_presign_final_exec(party);
  cmp_presign_clean(party);
}

int signature_verify(const scalar_t r, const scalar_t s, const scalar_t msg, const gr_elem_t pubkey)
{
  ec_group_t ec    = ec_group_new();
  gr_elem_t gen    = ec_group_generator(ec);
  scalar_t ord     = ec_group_order(ec);
  gr_elem_t result = group_elem_new(ec);

  scalar_t s_inv = scalar_new();
  scalar_inv(s_inv, s, ord);

  group_operation(result, NULL, gen, msg, ec);
  group_operation(result, result, pubkey, r, ec);
  group_operation(result, NULL, result, s_inv, ec);

  scalar_t project_x = scalar_new();
  group_elem_get_x(project_x, result, ec, ord);

  int is_valid = scalar_equal(project_x, r);

  group_elem_free(result);
  scalar_free(s_inv);
  scalar_free(project_x);
  ec_group_free(ec);

  return is_valid;
}

void execute_signing (cmp_party_t *parties[], uint64_t num_parties)
{
  scalar_t *r     = calloc(num_parties, sizeof(scalar_t)); 
  
  scalar_t s     = scalar_new();
  scalar_t msg   = scalar_new();
  scalar_t sigma = scalar_new();
  
  scalar_sample_in_range(msg, parties[0]->ec_order, 0);
  scalar_set_ul(s, 0);
  for (uint64_t i = 0; i < num_parties; ++i)
  {
    r[i] = scalar_new();
    //cmp_signature_share(r[i], sigma, parties[i], msg);
    scalar_add(s, s, sigma, parties[i]->ec_order);
    assert(scalar_equal(r[0], r[i]));
  }

  // Validate Signature
  
  gr_elem_t pubkey = group_elem_new(parties[0]->ec);
  get_public_key(pubkey, parties, num_parties);

  printBIGNUM("msg = ", msg, "\n");
  printBIGNUM("r = ", r[0], "\n");
  printBIGNUM("s = ", s, "\n");
  printECPOINT("pubkey = ", pubkey, parties[0]->ec, "\n", 1);

  assert(signature_verify(r[0], s, msg, pubkey));

  for (uint64_t i = 0; i < num_parties; ++i) scalar_free(r[i]);
  free(r);
  scalar_free(s);
  scalar_free(msg);
  scalar_free(sigma);
  group_elem_free(pubkey);
}

int PRINT_VALUES;
int PRINT_SECRETS;

void test_protocol(uint64_t party_index, uint64_t num_parties, int print_values, int print_secrets)
{
  PRINT_VALUES = print_values;
  PRINT_SECRETS = print_secrets;
  
  hash_chunk  sid = "Fireblocks";
  uint64_t    *party_ids = calloc(num_parties, sizeof(uint64_t));

  // Initialize party ids
  for (uint64_t i = 0; i < num_parties; ++i) party_ids[i] = i;
  
  // Initialize Parties
  cmp_party_t *party = cmp_party_new(party_index, num_parties, party_ids, sid);

  printf("\n\n# Key Generation\n\n");
  execute_key_generation(party);

  printf("\n\n# Refrsh and Auxliarty Information\n\n");
  execute_refresh_and_aux_info(party);

  printf("\n\n# PreSign\n\n");
  execute_presign(party);

  // printf("\n\n# Signing\n\n");
  // execute_signing(parties, num_parties);

  cmp_party_free(party);
  free(party_ids);
}