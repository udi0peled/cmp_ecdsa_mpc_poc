#include "tests.h"
#include "cmp_ecdsa_protocol.h"
#include <openssl/rand.h>

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
  scalar_to_bytes(alpha_bytes, range_byte_len, alpha);
  printHexBytes("alpha_bytes = 0x", alpha_bytes, range_byte_len, "\n");

  scalar_make_plus_minus(alpha, range);
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
  printECPOINT("# el[0] = ", el[0], ec, "\n", 0);
  printf("el[0] = secp256k1.G * exps[0]\n");

  group_operation(el[1], NULL, (const gr_elem_t) ec_group_generator(ec), exps[1], ec);  
  printECPOINT("# el[1] = ", el[1], ec, "\n", 0);
  printf("el[1] = secp256k1.G * exps[1]\n");
  
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

  paillier_public_key_t *pub = paillier_encryption_copy_public(priv);
  
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

  ring_pedersen_private_t *rped_priv = ring_pedersen_generate_param(p, q);
  ring_pedersen_public_t *rped_pub = ring_pedersen_copy_public(rped_priv);

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
  // scalar_make_plus_minus(s_exp, rped_pub->N);
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
  printHexBytes("data = ", zeros, sizeof(zeros), "");
  printHexBytes("", data, data_len, "\n");

  uint8_t *digest = malloc(digest_len);
  fiat_shamir_bytes(digest, digest_len, data, data_len);

  printf("digest = ");
  for (uint64_t i = 0; i < digest_len; i += 32)
  {
    printHexBytes("", digest + i, (digest_len - i <  32  ? digest_len - i : 32), " ");
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

  zkp_schnorr_t *zkp = zkp_schnorr_new();
  
  zkp->public.G = ec_group_new();
  zkp->public.g = ec_group_generator(zkp->public.G);
  zkp->public.X = group_elem_new(zkp->public.G);

  zkp->secret.x = scalar_new();
  scalar_sample_in_range(zkp->secret.x, ec_group_order(zkp->public.G), 0);

  group_operation(zkp->public.X, NULL, zkp->public.g, zkp->secret.x, zkp->public.G);

  scalar_t alpha = scalar_new();

  zkp_schnorr_commit(zkp, alpha);
  zkp_schnorr_prove(zkp, &aux, alpha);
  printf("# 1 == %d : valid\n", zkp_schnorr_verify(zkp, &aux));

  BN_add_word(alpha,1);
  zkp_schnorr_prove(zkp, &aux, alpha);
  printf("# 1 == %d : alpha changed\n", zkp_schnorr_verify(zkp, &aux));

  BN_add_word(zkp->secret.x,1);
  zkp_schnorr_prove(zkp, &aux, alpha);
  printf("# 0 == %d : wrond secret.x\n", zkp_schnorr_verify(zkp, &aux));

  BN_sub_word(zkp->secret.x,1);
  BN_add_word(zkp->proof.z, 1);
  printf("# 0 == %d : wrong z\n", zkp_schnorr_verify(zkp, &aux));

  aux.info = malloc(1);
  aux.info_len = 1;
  printf("# 0 == %d : wrong aux\n", zkp_schnorr_verify(zkp, &aux));
  
  free(aux.info);
  scalar_free(alpha);
  scalar_free(zkp->secret.x);
  group_elem_free(zkp->public.X);
  ec_group_free(zkp->public.G);
  zkp_schnorr_free(zkp);
}

void test_zkp_encryption_in_range(paillier_public_key_t *paillier_pub, ring_pedersen_public_t *rped_pub)
{
  printf("#  test encryption_in_range\n");
  zkp_aux_info_t aux;
  aux.info = NULL;
  aux.info_len = 0;

  zkp_encryption_in_range_t *zkp = zkp_encryption_in_range_new();

  zkp->public.G = ec_group_new();
  zkp->public.paillier_pub = paillier_pub;
  zkp->public.rped_pub = rped_pub;
  zkp->public.K = scalar_new();

  zkp->secret.k = scalar_new();
  zkp->secret.rho = scalar_new();

  scalar_t G_order = ec_group_order(zkp->public.G);

  scalar_sample_in_range(zkp->secret.k, G_order, 0);
  paillier_encryption_sample(zkp->secret.rho, paillier_pub);
  paillier_encryption_encrypt(zkp->public.K, zkp->secret.k, zkp->secret.rho, paillier_pub);

  printBIGNUM("k = ", zkp->secret.k, "\n");
  printBIGNUM("rho = ", zkp->secret.rho, "\n");
  printBIGNUM("K = ", zkp->public.K, "\n");

  zkp_encryption_in_range_prove(zkp, &aux);
  printf("# 1 == %d : valid \n", zkp_encryption_in_range_verify(zkp, &aux));

  BN_add_word(zkp->secret.k, 1);
  zkp_encryption_in_range_prove(zkp, &aux);
  printf("# 0 == %d : wrong secret.k\n", zkp_encryption_in_range_verify(zkp, &aux));

  BN_sub_word(zkp->secret.k, 1);
  BN_add_word(zkp->secret.rho, 1);
  zkp_encryption_in_range_prove(zkp, &aux);
  printf("# 0 == %d : wrong secret.rho\n", zkp_encryption_in_range_verify(zkp, &aux));

  scalar_t sample_range = scalar_new();
  BN_set_bit(sample_range, 8*ELL_ZKP_RANGE_PARAMETER_BYTES + 8*EPS_ZKP_SLACK_PARAMETER_BYTES );
  scalar_add(zkp->secret.k, zkp->secret.k, sample_range, zkp->public.paillier_pub->N);
  paillier_encryption_sample(zkp->secret.rho, paillier_pub);
  paillier_encryption_encrypt(zkp->public.K, zkp->secret.k, zkp->secret.rho, paillier_pub);
  zkp_encryption_in_range_prove(zkp, &aux);
  printf("# 0 == %d : too big secret\n", zkp_encryption_in_range_verify(zkp, &aux));

  aux.info = malloc(1);
  aux.info_len = 1;
  printf("# 0 == %d : wrong aux\n", zkp_encryption_in_range_verify(zkp, &aux));
  
  free(aux.info);
  scalar_free(sample_range);
  scalar_free(zkp->secret.k);
  scalar_free(zkp->secret.rho);
  scalar_free(zkp->public.K);
  ec_group_free(zkp->public.G);
  zkp_encryption_in_range_free(zkp);
}

#define NUM_PARTIES 3

void execute_key_generation (cmp_party_t *parties[])
{
  // Execute Key Generation for all
  for (uint64_t i = 0; i < NUM_PARTIES; ++i) cmp_key_generation_init(parties[i]);
  for (uint64_t i = 0; i < NUM_PARTIES; ++i) cmp_key_generation_round_1_exec(parties[i]);
  for (uint64_t i = 0; i < NUM_PARTIES; ++i) cmp_key_generation_round_2_exec(parties[i]);
  for (uint64_t i = 0; i < NUM_PARTIES; ++i) cmp_key_generation_round_3_exec(parties[i]);
  for (uint64_t i = 0; i < NUM_PARTIES; ++i) cmp_key_generation_final_exec(parties[i]);

  for (uint64_t i = 0; i < NUM_PARTIES; ++i)
  {
    cmp_key_generation_clean(parties[i]);
    printf("secret_%lu = ", parties[i]->id);
    printBIGNUM("", parties[i]->secret_x, "\n");
    printf("public_%lu = ", parties[i]->id);
    printECPOINT("secp256k1.Point(0x", parties[i]->public_X, parties[i]->sid->ec, ")\n", 1);
  }
}

void test_protocol()
{
  uint64_t party_ids[NUM_PARTIES] = {1, 2, 3};

  cmp_session_id_t *sid = cmp_session_id_new(1234, NUM_PARTIES, party_ids);
  cmp_party_t *parties[NUM_PARTIES];

  // Initialize Parties
  for (uint64_t i = 0; i < NUM_PARTIES; ++i) cmp_party_new(parties, NUM_PARTIES, i, party_ids[i], sid);

  execute_key_generation(parties);

  // Update sid byte to identify next phases

  cmp_session_id_append_bytes(sid, sid->srid, sizeof(hash_chunk));
  
  for (uint64_t i = 0; i < NUM_PARTIES; ++i) cmp_party_free(parties[i]);

  cmp_session_id_free(sid);
}