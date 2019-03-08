#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libcsidh.h"

int main() {
    csidh_private_key alice_priv, bob_priv;
    csidh_public_key alice_pub, bob_pub;
    csidh_public_key alice_shared, bob_shared;

    for (size_t i = 0; i < sizeof(csidh_public_key); i++)
        ((unsigned char*)&alice_shared)[i] = 0xff;

    csidh_generate(&alice_priv);
    csidh_generate(&bob_priv);

    csidh_derive(&alice_pub, &csidh_base, &alice_priv);
    csidh_derive(&bob_pub, &csidh_base, &bob_priv);

    csidh_derive(&alice_shared, &bob_pub, &alice_priv);
    csidh_derive(&bob_shared, &alice_pub, &bob_priv);


    if (memcmp(&alice_shared, &bob_shared, sizeof(csidh_public_key)))
        printf("\x1b[31mNOT EQUAL! :(\x1b[0m\n");
    else
        printf("\x1b[32mequal :)\x1b[0m\n");

    return 0;
}
