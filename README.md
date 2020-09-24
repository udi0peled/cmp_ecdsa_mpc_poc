# CMP - A Threshold ECDSA Multi-Party Computation Protocol

A standalone C implementation of the protocol in the article ["UC Non-Interactive, Proactive, Threshold ECDSA - Canetti, Makriyannis, Peled"](https://eprint.iacr.org/2020/492), together with relevant zero-knlowedge proofs.

### Disclaimer
This is a proof of concept and not a production-grade code, specifically:
* There is no error handling (of memory allocation failures etc).
* There is no implementation of communication between parties, all parties run in the same execution.
* If a malicious party is detected, only a message is printed and the protocol continues there is no handling of the failure.

The code is aimed towards simplicity and consistency with the article (in structure and variable names), and it hopefully clarifies the structure of the protocol and gives practical communication and computation.

### Prerequisites
* [OpenSSL](https://www.openssl.org/)

### Building

```
make benchmark
```

### Running

```
./benchmark cmp <num_players> <print_values>
```
The ```print_value``` is either 0 or 1, specifing whether to print all values (secret and public) computed by each party during protocol execution, which can be useful for debugging.

### Code Design
For more information consult the relevant h file

**algebraic_elements:**
An OpenSSL wrapper of basic algebraic functionalities.

**paillier_cryptosystem:**
Paillier cryptosystem operations: key generation, encrypting, decrypting and homomorphic evaluation.

**ring_pedersen_parameters:**
Ring pedersen evaluation: key generation and commiting.

**zkp_<...>:**
Zero knowledge proof of relevant claim. Allows proving and verifying claims, and for Schnorr proof also commiting before proving.

**cmp_protocol:**
All phases of the ECDSA protocol: key generation, refresh auxiliary information, pre-signing, signing.
Each of the phases is implemented in a few rounds, except signing which is non-interactive.


### License

???