#!/usr/bin/python3

def paillier_encrypt(pubN, plain, rand):
	modulos = pubN**2
	print(modulos)
	return (pow(pubN + 1, plain, modulos) * pow(rand, pubN, modulos)) % modulos