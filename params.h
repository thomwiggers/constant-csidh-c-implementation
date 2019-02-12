/*
 * params.h
 *
 *  Created on: 21 Jan 2019
 *      Author: sopmac
 */

#ifndef PARAMS_H_
#define PARAMS_H_

#include <unistd.h>

#define NUM_BATCHES 5
#define MY 11
#define NUM_ISOGENIES 763
const int8_t max[num_primes];

#define S 16
#define POWER_S 65536
#define T 128
#define BOUND (num_primes*(T/S) + 1)*(2*B)

typedef struct signature {
	private_key z[T/S];
    unsigned char b[32];
} signature;


//#define B 5 // B in [0,...,10]

#endif /* PARAMS_H_ */
