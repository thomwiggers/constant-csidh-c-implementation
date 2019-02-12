#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include "u512.h"
#include "fp.h"
#include "mont.h"
#include "csidh.h"
#include "seasign.h"
#include "cycle.h"
#include "params.h"

private_key seasign_private_key[POWER_S] = {0};
public_key seasign_public_key[POWER_S] = {0};

void u512_print(u512 const *x) {
	for (size_t i = 63; i < 64; --i)
		printf("%02hhx", i[(unsigned char *) x->c]);
}

void fp_print(fp const *x) {
	u512 y;
	fp_dec(&y, x);
	u512_print(&y);
}

void readFile(const char * filename, void * p, unsigned int length) {
	FILE *file;

	file = fopen(filename, "r+b");
	if (file == NULL) {
		(void) fprintf(stderr, "Could not open file.\n");
	} else {
		if(fread(p, 1, length, file) < length) {
			(void) fprintf(stderr, "Could not read %d bytes from file.\n", length);
		}
		(void) fclose(file);
	}

}

void CSIDH_test() {
    private_key priv_alice, priv_bob;
    public_key pub_alice, pub_bob;
    public_key shared_alice, shared_bob;
	clock_t t0, t1;

    printf("\ntesting CSIDH #########################################\n\n");
	csidh_private(&priv_alice, max);

    csidh_private(&priv_bob, max);

    t0 = clock();
    assert(csidh(&pub_alice, &base, &priv_alice, NUM_BATCHES));
    t1 = clock();

    printf("Alice's public key    (%7.3lf ms)\n", 1000. * (t1 - t0) / CLOCKS_PER_SEC);

    t0 = clock();
    assert(csidh(&pub_bob, &base, &priv_bob, NUM_BATCHES));
    t1 = clock();

    printf("Bob's public key      (%7.3lf ms)\n", 1000. * (t1 - t0) / CLOCKS_PER_SEC);

    t0 = clock();
    assert(csidh(&shared_alice, &pub_bob, &priv_alice, NUM_BATCHES));
    t1 = clock();

    printf("Alice's shared secret (%7.3lf ms)\n", 1000. * (t1 - t0) / CLOCKS_PER_SEC);

    t0 = clock();
    assert(csidh(&shared_bob, &pub_alice, &priv_bob, NUM_BATCHES));
    t1 = clock();

    printf("Bob's shared secret   (%7.3lf ms)\n  ", 1000. * (t1 - t0) / CLOCKS_PER_SEC);

    if (memcmp(&shared_alice, &shared_bob, sizeof(public_key)))
        printf("\x1b[31mNOT EQUAL!\x1b[0m\n");
    else
        printf("\x1b[32mequal.\x1b[0m\n");

}


int main() {


	clock_t t0, t1;

    FILE *pk_file;
    FILE *sk_file;
    FILE *sm_file;

	signature msg_sign;
	unsigned char msg[32] = {0};

	// calculate inverses for "elligatoring"
	// create inverse of u^2 - 1 : from 2 - 11
	for (int i = 2; i <= 20; i++) {
		fp_set(&invs_[i - 2], i);
		fp_sq1(&invs_[i - 2]);
		fp_sub2(&invs_[i - 2], &fp_1);
		fp_inv(&invs_[i - 2]);
	}

	CSIDH_test();

    printf("\nSeaSign ##########################################\n\n");

//+++++++++++++++++++++++++++++++++++++++++++

//		t0 = clock();
//		keygen(seasign_private_key, seasign_public_key, &base);
//		t1 = clock();
//	    printf("\rKey generation (including validation)  (%ld s)\n", (t1 - t0) / CLOCKS_PER_SEC);
//
//	    pk_file = fopen("pub_seasign.key", "rb+");
//		if (pk_file == NULL) {
//			pk_file = fopen("pub_seasign.key", "wb");
//		}
//		fwrite(&seasign_public_key, 1, sizeof(seasign_public_key), pk_file);
//		fclose(pk_file);

		readFile("pub_seasign.key", &seasign_public_key, sizeof(seasign_public_key));

//		sk_file = fopen("priv_seasign.key", "rb+");
//		if (sk_file == NULL) {
//			sk_file = fopen("priv_seasign.key", "wb");
//		}
//		fwrite(&seasign_private_key, 1, sizeof(seasign_private_key), sk_file);
//		fclose(sk_file);

		//memset(&seasign_private_key, 1, sizeof(seasign_private_key));

		readFile("priv_seasign.key", &seasign_private_key, sizeof(seasign_private_key));

		t0 = clock();
		while(!sign(&msg_sign, msg, &base, seasign_private_key)) {
			t1 = clock();
			printf("\rRejection by signing                 (%ld s)\n", (t1 - t0) / CLOCKS_PER_SEC);
		}
		t1 = clock();
		printf("\rSigning                              (%ld s)\n", (t1 - t0) / CLOCKS_PER_SEC);


		sm_file = fopen("signed_seasign.key", "rb+");
		if (sm_file == NULL) {
			sm_file = fopen("signed_seasign.key", "wb");
		}
		fwrite(&msg_sign, 1, sizeof(msg_sign), sm_file);
		fclose(sm_file);

		//readFile("signed_seasign.key", &msg_sign, sizeof(signature));

		t0 = clock();
		if(verify(&msg_sign, msg, seasign_public_key)){
			t1 = clock();
			printf("Verification: valid signature        (%ld s)\n", (t1 - t0) / CLOCKS_PER_SEC);
		} else {
			t1 = clock();
			printf("Verification: invalid signature      (%ld s)\n", (t1 - t0) / CLOCKS_PER_SEC);
		}



		t0 = clock();
		msg[30] ^= 1;
		if(verify(&msg_sign, msg, seasign_public_key)){
			t1 = clock();
			printf("Verification: flipping a bit DID NOT invalidate signature! (%ld s)\n", (t1 - t0) / CLOCKS_PER_SEC);
		} else {
			t1 = clock();
			printf("Verification: flipping a bit invalidate signature (%ld s)\n", (t1 - t0) / CLOCKS_PER_SEC);
		}

	
}
