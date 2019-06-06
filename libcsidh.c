#include "libcsidh.h"

#include <unistd.h>

#include "csidh.h"
#include "fp.h"
#include "u512.h"

const uint8_t MY = 11;
const int8_t MAX[num_primes] = {
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  8,  8,  8,
    8,  8,  8,  8,  11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    11, 11, 11, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
    13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 5,  7,  7,  7,  7};

const unsigned int NUM_BATCHES = 5;
const unsigned int NUM_ISOGENIES = 763;

int csidh_generate(csidh_private_key *key) {
  csidh_init();
  csidh_private((private_key *)key, MAX);
  return 0;
}

int csidh_derive(csidh_public_key *parameter, csidh_public_key const *base,
                 csidh_private_key const *key) {
  csidh_init();
  return !csidh((public_key *)parameter, (public_key *)base, (private_key *)key,
                NUM_BATCHES, MAX, NUM_ISOGENIES, MY);
}

const csidh_public_key csidh_base = {0};
