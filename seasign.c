/*
 * seasign.c
 *
 *  Created on: 21 Jan 2019
 *      Author: sopmac
 */

#include "seasign.h"
#include "csidh.h"
#include "cycle.h"
#include <openssl/sha.h>
#include <stdio.h>

const int8_t max[num_primes] = { 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	                7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11,11, 11,
	                11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 13, 13, 13, 13,
	                13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
	                13, 13, 13, 13, 13, 13, 13, 13, 5, 7, 7, 7, 7 };

clock_t t0, t1;

void keygen(private_key *priv, public_key *out, public_key const *in) {
	//public_key local = {0};

	min_exp = (num_primes*T + 1)*(B);
	max_exp = 0;
	for(uint32_t i=0; i < (POWER_S); i++) {
		t0 = clock();
		csidh_private(&priv[i], max);
		assert(csidh(&out[i], in, &priv[i], NUM_BATCHES));
		t1 = clock();
	    printf("\rKey generation  #%d (%7.3lf ms)\n", i, 1000. * (t1 - t0) / CLOCKS_PER_SEC);
	}
}

bool sign(signature *sign, const unsigned char msg[32],
		const public_key *base, private_key *priv) {

	uint16_t k = 0;
	public_key jInv[T/S];
	//public_key _jInv[t/s];
	unsigned char toHash[sizeof(jInv) + 32] = {0};

	memset(jInv, 0, sizeof(jInv));

	for (uint8_t i = 0; i < (T/S); i++) {
		randomK(&sign->z[i]);
		t0 = clock();
		assert(csidh(&jInv[i], base, &sign->z[i], NUM_BATCHES));
		t1 = clock();
		printf("\rsigning %d-bit block #%d   (%ld s)\n", S, i, (t1 - t0) / CLOCKS_PER_SEC);

		memcpy(toHash + (sizeof(public_key) * i),  &jInv[i].A.x, sizeof(public_key));

	}
	memcpy(toHash + (sizeof(toHash) - 32), msg, 32);
	t0 = clock();
	//b_1 || ... || b_t	= H(j(E_1),...,j(E_t),msg)
	SHA256(toHash, sizeof(toHash), sign->b);

	for (uint8_t i = 0; i < (T/S); i++) {
		k = sign->b[i] << 8 & 0xffff;
		k = k + (int) sign->b[i+1];
		for (uint8_t j = 0; j < num_primes; j++) {
			sign->z[i].e[j] = sign->z[i].e[j] - priv[k].e[j];
			if((sign->z[i].e[j] < 0) || (sign->z[i].e[j] > (BOUND))) {
				t1 = clock();
				printf("\rrejection by signing %d-bit block #%d   (%ld s)\n", S, i, (t1 - t0) / CLOCKS_PER_SEC);
				return false;
			}
		}
	}
	t1 = clock();
	printf("\rfurther steps@sign                      (%ld s)\n",  (t1 - t0) / CLOCKS_PER_SEC);
	return true;

}

bool verify(const signature *sign, const unsigned char msg[32], const public_key *publ) {

	public_key jInv[T/S];
	unsigned char toHash[sizeof(jInv) + 32] = {0};
	unsigned char b[32];
	uint16_t k = 0;

	for (uint8_t i = 0; i < T/S; i++) {
		k = sign->b[i] << 8 & 0xffff;
		k = k + (int) sign->b[i+1];
		t0 = clock();
		assert(csidh(&jInv[i], &publ[k], &sign->z[i], NUM_BATCHES));
		t1 = clock();
		printf("\rverifying %d-bit block #%d   (%ld s)\n", S, i, (t1 - t0) / CLOCKS_PER_SEC);
//		if (!validate(&jInv[i])) {
//			printf("VERIFY: invalid keys!!!\n");
//		}


		memcpy(toHash + (sizeof(public_key) * i),  &jInv[i].A.x, sizeof(public_key));
	}
	memcpy(toHash + (sizeof(toHash) - 32), msg, 32);

	//b_1 || ... || b_t	= H(j(E_1),...,j(E_t),msg)
	SHA256(toHash, sizeof(toHash), b);

	if(!(memcmp(sign->b, b, 32))) {
		return true;
	} else {
		return false;
	}


}


void randomK(private_key *out) {
	//0, (nt+ 1)2*B

	memset(&out->e, 0, sizeof(out->e));

	for (size_t i = 0; i < num_primes;) {
		uint32_t buf[1024];
		randombytes(buf, sizeof(buf));

		for (size_t j = 0; j < sizeof(buf); ++j) {
			out->e[i] = (buf[j]%BOUND);
			if (++i >= num_primes)
				break;
		}
	}
}
