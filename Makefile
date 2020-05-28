Bench_Name := benchmark

App_C_Flags := -g -O0 -Wall -Wextra -Wvla -Wno-unknown-pragmas -I.
App_Cpp_Flags := $(App_C_Flags) -std=c++14
App_Link_Flags := -lcrypto

all: $(Bench_Name)

benchmark.o: benchmark.c common.o tests.o primitives.o 
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

cmp_ecdsa_protocol.o: cmp_ecdsa_protocol.c cmp_ecdsa_protocol.h common.o primitives.o 
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

tests.o: tests.c tests.h common.o primitives.o 
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

common.o: common.c common.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

algebraic_elements.o: algebraic_elements.c algebraic_elements.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

paillier_cryptosystem.o: paillier_cryptosystem.c paillier_cryptosystem.h algebraic_elements.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

ring_pedersen_parameters.o: ring_pedersen_parameters.c ring_pedersen_parameters.h paillier_cryptosystem.o algebraic_elements.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_common.o: zkp_common.c zkp_common.h algebraic_elements.o paillier_cryptosystem.o ring_pedersen_parameters.o 
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_paillier_blum_modulus.o: zkp_paillier_blum_modulus.c zkp_paillier_blum_modulus.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_ring_pedersen_param.o: zkp_ring_pedersen_param.c zkp_ring_pedersen_param.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_schnorr.o: zkp_schnorr.c zkp_schnorr.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_encryption_in_range.o: zkp_encryption_in_range.c zkp_encryption_in_range.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_group_vs_paillier_range.o: zkp_group_vs_paillier_range.c zkp_group_vs_paillier_range.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_operation_group_commitment_range.o: zkp_operation_group_commitment_range.c zkp_operation_group_commitment_range.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

zkp_operation_paillier_commitment_range.o: zkp_operation_paillier_commitment_range.c zkp_operation_paillier_commitment_range.h zkp_common.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

primitives.o: algebraic_elements.o paillier_cryptosystem.o ring_pedersen_parameters.o  zkp_common.o zkp_paillier_blum_modulus.o zkp_ring_pedersen_param.o zkp_schnorr.o zkp_encryption_in_range.o zkp_group_vs_paillier_range.o zkp_operation_group_commitment_range.o zkp_operation_paillier_commitment_range.o
	@$(LD) -relocatable $^ -o $@
	@echo "LINK =>  $@"


$(Bench_Name): common.o tests.o primitives.o cmp_ecdsa_protocol.o benchmark.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -rf $(Bench_Name) *.o