/*
 * seasign.h
 *
 *  Created on: 21 Jan 2019
 *      Author: sopmac
 */

#ifndef SEASIGN_H_
#define SEASIGN_H_

#include "fp.h"
#include "rng.h"
#include "csidh.h"
#include "params.h"
#include <assert.h>
#include <string.h>

void keygen(private_key *priv, public_key *pub, public_key const *in);
bool sign(signature *sign, const unsigned char msg[32], const public_key *base, private_key *priv);
bool verify(const signature *sign, const unsigned char msg[32], const public_key *publ);
void randomK(private_key *out);



#endif /* SEASIGN_H_ */
