#ifndef CSIDH_H
#define CSIDH_H

#include "u512.h"
#include "fp.h"
#include "mont.h"

/* specific to p, should perhaps be somewhere else */
#define num_primes 74
//#define max_exponent 10 /* (2*5+1)^74 is roughly 2^256 */
fp invs_[10];

void csidh_init();

typedef struct private_key {
    //int8_t e[(num_primes + 1) / 2]; /* packed int4_t */
    int8_t e[num_primes]; /* packed int4_t */
} private_key;

typedef struct public_key {
    fp A; /* Montgomery coefficient: represents y^2 = x^3 + Ax^2 + x */
} public_key;

extern const public_key base;

void csidh_private(private_key *priv, const uint8_t *max_exponent);
void action(public_key *out, public_key const *in, private_key const *priv,
		uint8_t num_intervals, uint8_t const *max_exponent, unsigned int const num_isogenies, uint8_t const my);
bool csidh(public_key *out, public_key const *in, private_key const *priv,
		uint8_t const num_intervals, uint8_t const *max_exponent, unsigned int const num_isogenies, uint8_t const my);
void elligator(fp * x, const fp *A, bool sign, uint8_t index);
bool validate(public_key const *in);

#endif
