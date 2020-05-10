Bench_Name := benchmark

App_C_Flags := -g -O0 -Wall -Wextra -Wvla -Wno-unknown-pragmas -I.
App_Cpp_Flags := $(App_C_Flags) -std=c++14
App_Link_Flags := -lcrypto

all: $(Bench_Name)

benchmark.o: benchmark.c common.o tests.o primitives.o 
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

tests.o: tests.c tests.h common.o primitives.o 
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

common.o: common.c common.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

primitives.o: primitives.c primitives.h
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Bench_Name): benchmark.o primitives.o common.o tests.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

clean:
	@rm -rf $(Bench_Name) *.o