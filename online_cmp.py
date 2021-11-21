#! /usr/bin/python3

EC_BYTES = 256//8
PED_BYTES = 1024//8
PAILLIER_BYTES = 2048//8

withPedersenModProof = 1 # set to 1 if not including "No small factors" proof for Pedersen modulus during setup
withBatchProving = 1 

def balanced_online_cmp_signing(n):
    r1 = bocmp_round1(n)
    r2 = bocmp_round2(n)
    r3 = bocmp_round3(n)
    r4 = bocmp_round4(n)

    return (r1, r2, r3, r4)

def bocmp_round4(n):
    return EC_BYTES

def bocmp_round3(n):
    delta = EC_BYTES
    Delta = EC_BYTES
    phi_hat = zkp_ddh()

    return delta + Delta + phi_hat


def bocmp_round2(n):
    Gamma = EC_BYTES
    D = 2*PAILLIER_BYTES
    F = 2*PAILLIER_BYTES # Can move to round 1
    D_hat = 2*PAILLIER_BYTES
    F_hat = 2*PAILLIER_BYTES  # Can move to round 1
    psi = zkp_affg()
    psi_hat = zkp_affg() * (1-withBatchProving)
    phi = zkp_ddh()

    return Gamma + phi + (n-1)*(D + F + D_hat + F_hat + psi + psi_hat)


def bocmp_round1(n):
    K = PAILLIER_BYTES
    G = PAILLIER_BYTES
    A = EC_BYTES
    B = EC_BYTES
    Z = EC_BYTES
    W = EC_BYTES
    Lambda = EC_BYTES
    psi0 = zkp_Rddh()
    psi1 = zkp_Rddh()

    return K + G + A + B + Z + W + Lambda + (n-1) * (psi0 + psi1)


ell = EC_BYTES
eps = ell + 64
ell_p = 2*ell + eps + 64

def zkp_Rddh():
    S = PED_BYTES
    T = PED_BYTES
    D = 2*PAILLIER_BYTES
    Y = EC_BYTES
    Z = EC_BYTES

    z1 = ell + eps 
    w  = EC_BYTES
    z2 = PAILLIER_BYTES
    z3 = eps + PED_BYTES + (1-withPedersenModProof) * ell

    return S + T + D + Y + Z + z1 + w + z2 + z3


def zkp_affg():
    S = PED_BYTES
    T = PED_BYTES
    A = 2*PAILLIER_BYTES
    Bx = EC_BYTES
    By = 2*PAILLIER_BYTES 
    E = PED_BYTES
    F = PED_BYTES

    z1 = ell + eps
    z2 = ell_p + eps
    z3 = eps + PED_BYTES + (1-withPedersenModProof) * ell
    z4 = eps + PED_BYTES + (1-withPedersenModProof) * ell
    w  = PAILLIER_BYTES
    wy = PAILLIER_BYTES 

    return S + T + A + Bx + By + E + F + z1 + z2 + z3 + z4 + w + wy


def zkp_ddh():
    D = EC_BYTES
    Y = EC_BYTES
    V = EC_BYTES
    z = EC_BYTES
    w = EC_BYTES

    return D + Y + V + z + w