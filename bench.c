#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "csidh.h"
#include "cycle.h"
#include "fp.h"
#include "mont.h"
#include "u512.h"

#include <inttypes.h>

static __inline__ uint64_t rdtsc(void) {
  uint32_t hi, lo;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return lo | (uint64_t)hi << 32;
}

unsigned long its = 1000;

int main() {
  clock_t t0, t1, time = 0;
  uint64_t c0, c1, cycles = 0;
  uint64_t allticks = 0;
  ticks ticks1, ticks2;

  uint8_t num_batches = 5;
  uint8_t my = 11;

  int8_t max[num_primes] = {7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
                            7,  7,  7,  8,  8,  8,  8,  8,  8,  8,  11, 11, 11,
                            11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
                            11, 11, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
                            13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
                            13, 13, 13, 13, 5,  7,  7,  7,  7};

  unsigned int num_isogenies = 763;

  // calculate inverses for "elligatoring"
  // create inverse of u^2 - 1 : from 2 - 11
  for (int i = 2; i <= 10; i++) {
    fp_set(&invs_[i - 2], i);
    fp_sq1(&invs_[i - 2]);
    fp_sub2(&invs_[i - 2], &fp_1);
    fp_inv(&invs_[i - 2]);
  }

  private_key priv;
  public_key pub = base;

  for (unsigned long i = 0; i < its; ++i) {

    csidh_private(&priv, max);

    t0 = clock();
    c0 = rdtsc();
    ticks1 = getticks();
    /**************************************/
    // assert(validate(&pub));
    action(&pub, &pub, &priv, num_batches, max, num_isogenies, my);
    /**************************************/
    ticks2 = getticks();
    allticks = allticks + elapsed(ticks2, ticks1);
    c1 = rdtsc();
    t1 = clock();
    cycles += c1 - c0;
    time += t1 - t0;
    if (i % 100 == 0) {
      printf("Iteration: %lu\n", i);
    }
  }

  printf("iterations: %lu\n", its);
  printf("clock cycles: %" PRIu64 " (rdtsc)\n", (uint64_t)cycles / its);
  printf("clock cycles: %" PRIu64 " (getticks)\n", (uint64_t)allticks / its);

  printf("wall-clock time: %.3lf ms\n", 1000. * time / CLOCKS_PER_SEC / its);
  return 0;
}
