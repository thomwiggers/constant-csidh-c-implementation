#ifndef CSIDH_H
#define CSIDH_H

#include "u512.h"
#include "fp.h"
#include "mont.h"

/* specific to p, should perhaps be somewhere else */
#define num_primes 74

//#define max_exponent 10 /* (2*5+1)^74 is roughly 2^256 */
fp invs_[10];

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define B 5

uint16_t min_exp;
uint16_t max_exp;

const unsigned primes[num_primes];

typedef struct private_key {
	//int8_t e[num_primes];
	int32_t e[num_primes];
} private_key;

typedef struct random_key {
	//int8_t e[num_primes];
	int32_t e[num_primes];
} random_key;

typedef struct public_key {
    fp A; /* Montgomery coefficient: represents y^2 = x^3 + Ax^2 + x */
} public_key;

extern const public_key base;

void csidh_private(private_key *priv, const int8_t *max_exponent);
void action(public_key *out, public_key const *in, private_key const *priv, uint8_t num_batches);
bool csidh(public_key *out, public_key const *in, private_key const *priv, uint8_t const num_batches);
void elligator(fp * x, const fp *A, bool sign, uint8_t index);
bool validate(public_key const *in);


uint32_t lookup(size_t pos, int32_t const *priv);
uint32_t isequal(uint32_t a, uint32_t b);
void cmov(int32_t *r, const int32_t *a, uint32_t b);


#endif
