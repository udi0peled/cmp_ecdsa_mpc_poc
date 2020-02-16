#include "nikmak_ecdsa_mpc_poc.h"
#include <assert.h>

protocol_ctx_t *ctx;

int main()
{
  ctx = protocol_ctx_new();

  protocol_ctx_free(ctx);  
}