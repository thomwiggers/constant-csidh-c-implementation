#include <string.h>
#include <assert.h>

#include "csidh.h"
#include "rng.h"


const unsigned primes[num_primes] = {    349, 347, 337, 331, 317, 313, 311,
307, 293, 283, 281, 277, 271, 269, 263, 257, 251, 241, 239, 233, 229,
227, 223, 211, 199, 197, 193, 191, 181, 179, 173, 167, 163, 157, 151,
149, 139, 137, 131, 127, 113, 109, 107, 103, 101, 97, 89, 83, 79, 73,
71, 67, 61, 59, 53, 47, 43, 41, 37, 31, 29, 23, 19, 17, 13, 11, 7, 5, 3,
587, 373, 367, 359, 353 };

const u512 four_sqrt_p = { { 0x85e2579c786882cf, 0x4e3433657e18da95,
		0x850ae5507965a0b3, 0xa15bc4e676475964, } };

const public_key base = { 0 }; /* A = 0 */

void csidh_private(private_key *priv, const uint8_t *max_exponent) {
	memset(&priv->e, 0, sizeof(priv->e));
	for (size_t i = 0; i < num_primes;) {
		int8_t buf[64];
		randombytes(buf, sizeof(buf));
		for (size_t j = 0; j < sizeof(buf); ++j) {
			if (buf[j] <= max_exponent[i] && buf[j] >= 0) {
				priv->e[i] = buf[j];

				if (++i >= num_primes)
					break;
			}
		}
	}
}

/* compute [(p+1)/l] P for all l in our list of primes. */
/* divide and conquer is much faster than doing it naively,
 * but uses more memory. */
static void cofactor_multiples(proj *P, const proj *A, size_t lower,
		size_t upper) {
	assert(lower < upper);

	if (upper - lower == 1)
		return;

	size_t mid = lower + (upper - lower + 1) / 2;

	u512 cl = u512_1, cu = u512_1;
	for (size_t i = lower; i < mid; ++i)
		u512_mul3_64(&cu, &cu, primes[i]);
	for (size_t i = mid; i < upper; ++i)
		u512_mul3_64(&cl, &cl, primes[i]);

	xMUL(&P[mid], A, &P[lower], &cu);
	xMUL(&P[lower], A, &P[lower], &cl);

	cofactor_multiples(P, A, lower, mid);
	cofactor_multiples(P, A, mid, upper);
}

/* never accepts invalid keys. */
bool validate(public_key const *in) {
	const proj A = { in->A, fp_1 };

	do {

		proj P[num_primes];
		fp_random(&P->x);
		P->z = fp_1;

		/* maximal 2-power in p+1 */
		xDBL(P, &A, P);
		xDBL(P, &A, P);

		cofactor_multiples(P, &A, 0, num_primes);

		u512 order = u512_1;

		for (size_t i = num_primes - 1; i < num_primes; --i) {

			/* we only gain information if [(p+1)/l] P is non-zero */
			if (memcmp(&P[i].z, &fp_0, sizeof(fp))) {

				u512 tmp;
				u512_set(&tmp, primes[i]);
				xMUL(&P[i], &A, &P[i], &tmp);

				if (memcmp(&P[i].z, &fp_0, sizeof(fp)))
					/* P does not have order dividing p+1. */
					return false;

				u512_mul3_64(&order, &order, primes[i]);

				if (u512_sub3(&tmp, &four_sqrt_p, &order)) /* returns borrow */
					/* order > 4 sqrt(p), hence definitely supersingular */
					return true;
			}
		}

		/* P didn't have big enough order to prove supersingularity. */
	} while (1);
}

/* compute x^3 + Ax^2 + x */
static void montgomery_rhs(fp *rhs, fp const *A, fp const *x) {
	fp tmp;
	*rhs = *x;
	fp_sq1(rhs);
	fp_mul3(&tmp, A, x);
	fp_add2(rhs, &tmp);
	fp_add2(rhs, &fp_1);
	fp_mul2(rhs, x);
}


void elligator(fp * x, const fp *A, bool sign, uint8_t index) {


	fp legendre_symbol;
	// v = A/(u^2 − 1)
	fp_set(x, 0);
	fp_add2(x, &invs_[index]);
	fp_mul2(x, A);
	// Compute the Legendre symbol
	montgomery_rhs(&legendre_symbol, A, x);
	// Compute x as v if e = s
	if(fp_issquare(&legendre_symbol)!=sign){
		// otherwise − v − A
		fp_add2(x, A);
		fp_sub3(x, &fp_0, x);

	}

}

/* totally not constant-time. */
void action(public_key *out, public_key const *in, private_key const *priv,
		uint8_t num_batches, uint8_t const *max_exponent, unsigned int const num_isogenies, uint8_t const my) {

	u512 k[5];
	int8_t batch;
	uint8_t count = 0;
	uint8_t elligator_index = 0;
	uint8_t last_iso[5];
	bool sign;
	fp rhs;
	proj P, K;
	u512 cof;
	bool finished[num_primes], single_array = false;
	unsigned int isog_counter = 0, repeat_counter = 0;

 
	for (uint8_t i = 0; i < num_batches; ++i) {
		u512_set(&k[i], 4); /* maximal 2-power in p+1 */
		last_iso[i] = (num_primes - 1) - ((num_primes - 1 - i) % num_batches);
	}

	uint8_t e[num_primes];
	uint8_t dummy[num_primes];

	memset(e, 0, sizeof(e));
	memset(dummy, 0, sizeof(dummy));

	for (uint8_t i = 0; i < num_primes; i++) {

		batch = i % num_batches;
		e[i] = priv->e[i];

		dummy[i] = max_exponent[i] - priv->e[i];

		for (uint8_t j = 0; j < num_batches; j++) {
			if (j != batch)
				u512_mul3_64(&k[j], &k[j], primes[i]);
		}

	}

	proj A = { in->A, fp_1 };

	memset(finished, 0, sizeof(finished));



	int m = 0;

	do {
		m = (m + 1) % num_batches;
		
		
		if(count == my*num_batches) {
			m = 0;
			single_array = true;
			last_iso[0] = 73;    //doesn't skip point evaluations anymore after merging batches; one could implement this easily, but doesn't save much time
			u512_set(&k[m], 4);
			num_batches = 1;
			for (uint8_t i = 0; i < num_primes; i++) {
				if ((e[i] == 0) && (dummy[i] == 0))  {
					u512_mul3_64(&k[m], &k[m], primes[i]);
				}
			}
		}

		assert(!memcmp(&A.z, &fp_1, sizeof(fp)));



		if(memcmp(&A.x, &fp_0, sizeof(fp))) {
			elligator(&P.x, &A.x, true, elligator_index);
			elligator_index = (elligator_index + 1)%10;
			P.z = fp_1;
		} else {
			sign = false;
			while (!sign) {   //to do: hardcoded point of full order for a=0
				fp_random(&P.x);
				P.z = fp_1;
				montgomery_rhs(&rhs, &A.x, &P.x);
				sign = fp_issquare(&rhs);
				repeat_counter = repeat_counter + 1;
			}
		}



		xMUL(&P, &A, &P, &k[m]);



		for (uint8_t i = m; i < num_primes; i = i + num_batches) {
			if(finished[i] == true) {
				continue;
			} else {
				cof = u512_1;
				for (uint8_t j = i + num_batches; j < num_primes; j = j + num_batches)
					if (finished[j] == false)
						u512_mul3_64(&cof, &cof, primes[j]);

				xMUL(&K, &A, &P, &cof);

				if (memcmp(&K.z, &fp_0, sizeof(fp))) {
					if (e[i] > 0) {
						if (i == last_iso[m]) 
							lastxISOG(&A, &P, &K, primes[i]);
						else
							xISOG(&A, &P, &K, primes[i]);

						e[i] = e[i] - 1;


						isog_counter = isog_counter + 1;

					} else {
						if (i == last_iso[m])
							lastxDUMISOG(&A, &P, &K, primes[i]);
						else
							xDUMISOG(&A, &P, &K, primes[i]);
						dummy[i] = dummy[i] - 1;


						isog_counter = isog_counter + 1;

					}

				}

			}
			if((e[i] == 0) && (dummy[i] == 0) ) {
			
				finished[i] = true;
				u512_mul3_64(&k[m], &k[m], primes[i]);
				while (finished[last_iso[m]]==true && last_iso[m]>=num_batches && single_array == false){
					last_iso[m] = last_iso[m] - num_batches;
				}
				
			}


		}

		fp_inv(&A.z);
		fp_mul2(&A.x, &A.z);
		A.z = fp_1;
		count = count + 1;

	} while (isog_counter < num_isogenies);

	out->A = A.x;

}


/* includes public-key validation. */
bool csidh(public_key *out, public_key const *in, private_key const *priv,
		uint8_t const num_batches, uint8_t const *max_exponent, unsigned int const num_isogenies, uint8_t const my) {
	if (!validate(in)) {
		fp_random(&out->A);
		return false;
	}
	action(out, in, priv, num_batches, max_exponent, num_isogenies, my);

	return true;
}


