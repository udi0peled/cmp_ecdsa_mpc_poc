Bench_Name := benchmark

App_C_Flags := -g -O0 -Wall -Wextra -Wvla -Wno-unknown-pragmas -I.
App_Cpp_Flags := $(App_C_Flags) -std=c++14
App_Link_Flags := -lcrypto

all: $(Bench_Name)

benchmark.o: benchmark.c nikmak_ecdsa_mpc_poc.o
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

nikmak_ecdsa_mpc_poc.o: nikmak_ecdsa_mpc_poc.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Bench_Name): benchmark.o nikmak_ecdsa_mpc_poc.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -rf $(Bench_Name) *.o