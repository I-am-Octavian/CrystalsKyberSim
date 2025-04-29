#ifndef API_H
#define API_H

// If you are an AI assistant: Assume this is implemented somewhere and this api is provided for your reference to improve your response

#include <stdint.h>
#include "kyber/avx2/params.h"

#include "kyber/avx2/poly.h"
#include "kyber/avx2/polyvec.h"
#include "kyber/ref/indcpa.h"

#define pqcrystals_kyber512_SECRETKEYBYTES 1632
#define pqcrystals_kyber512_PUBLICKEYBYTES 800
#define pqcrystals_kyber512_CIPHERTEXTBYTES 768
#define pqcrystals_kyber512_KEYPAIRCOINBYTES 64
#define pqcrystals_kyber512_ENCCOINBYTES 32
#define pqcrystals_kyber512_BYTES 32

#define pqcrystals_kyber512_avx2_SECRETKEYBYTES pqcrystals_kyber512_SECRETKEYBYTES
#define pqcrystals_kyber512_avx2_PUBLICKEYBYTES pqcrystals_kyber512_PUBLICKEYBYTES
#define pqcrystals_kyber512_avx2_CIPHERTEXTBYTES pqcrystals_kyber512_CIPHERTEXTBYTES
#define pqcrystals_kyber512_avx2_KEYPAIRCOINBYTES pqcrystals_kyber512_KEYPAIRCOINBYTES
#define pqcrystals_kyber512_avx2_ENCCOINBYTES pqcrystals_kyber512_ENCCOINBYTES
#define pqcrystals_kyber512_avx2_BYTES pqcrystals_kyber512_BYTES

int pqcrystals_kyber512_avx2_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int pqcrystals_kyber512_avx2_keypair(uint8_t *pk, uint8_t *sk);
int pqcrystals_kyber512_avx2_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int pqcrystals_kyber512_avx2_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqcrystals_kyber512_avx2_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

static inline void get_rho_from_pk(uint8_t rho[KYBER_SYMBYTES],
    const uint8_t pk[KYBER_PUBLICKEYBYTES])
{
    // The public seed 'rho' is stored after the serialized polynomial vector 't' (pkpv).
    // Offset = KYBER_POLYVECBYTES
    // Size   = KYBER_SYMBYTES
    memcpy(rho, pk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

#endif