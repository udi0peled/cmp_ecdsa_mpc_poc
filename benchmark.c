#include "nikmak_ecdsa_mpc_poc.h"

group_ctx_t *ctx;

int main()
{
  ctx = group_ctx_new();
  
  group_ctx_free(ctx);  
}