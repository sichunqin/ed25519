#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* #define ED25519_DLL */
#include "src/ed25519.h"

#include "src/ge.h"
#include "src/sc.h"

/*
# Test Vector
# Private key: 0xe59964067f8da772aa66db8bb4c990103203feccce3cf7e24b38da82c43100f5
# Public key:  5c4af42f8dc436036d0e0a0010a064e139222858b79e8c1c0be061dd7f8ae4fd
# Message:  Hello
# Signature: 4ac329357f7cc2141255561bbed326ad5ab1582c4c93197eeec79ecf00ac01eb35293b365ff1431c10d40bd028c39fae185c86931fc51a8eeff40ed533f5ad05
  test2 is used to verify against the est vector.
  Normally seed is used for private key (32 bytess.) But the libary uses sha-512(seed) as private key.
*/

extern void printCharInHexadecimal(const char* str, int len);

void test1(){
    unsigned char public_key[32], private_key[64], seed[32], scalar[32];
    unsigned char other_public_key[32], other_private_key[64];
    unsigned char shared_secret[32], other_shared_secret[32];
    unsigned char signature[64];

    clock_t start;
    clock_t end;
    int i;

    const unsigned char message[] = "Hello, world!";
    const int message_len = strlen((char*) message);

    /* create a random seed, and a keypair out of that seed */
    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);

    printf("Public Key: ");
    printCharInHexadecimal(public_key,32);
    printf("Private Key: ");
    printCharInHexadecimal(private_key,64);

    printf("Message: ");
    printCharInHexadecimal(message,message_len);

    /* create signature on the message with the keypair */
    ed25519_sign(signature, message, message_len, public_key, private_key);

    printf("Message Signature: ");
    printCharInHexadecimal(signature, 64);
    /* verify the signature */
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }

    /* create scalar and add it to the keypair */
    ed25519_create_seed(scalar);
    ed25519_add_scalar(public_key, private_key, scalar);

    /* create signature with the new keypair */
    ed25519_sign(signature, message, message_len, public_key, private_key);

    /* verify the signature with the new keypair */
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("valid signature\n");
    } else {
        printf("invalid signature\n");
    }

    /* make a slight adjustment and verify again */
    signature[44] ^= 0x10;
    if (ed25519_verify(signature, message, message_len, public_key)) {
        printf("did not detect signature change\n");
    } else {
        printf("correctly detected signature change\n");
    }

    /* generate two keypairs for testing key exchange */
    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);
    ed25519_create_seed(seed);
    ed25519_create_keypair(other_public_key, other_private_key, seed);

    /* create two shared secrets - from both perspectives - and check if they're equal */
    ed25519_key_exchange(shared_secret, other_public_key, private_key);
    ed25519_key_exchange(other_shared_secret, public_key, other_private_key);

    for (i = 0; i < 32; ++i) {
        if (shared_secret[i] != other_shared_secret[i]) {
            printf("key exchange was incorrect\n");
            break;
        }
    }

    if (i == 32) {
        printf("key exchange was correct\n");
    }

    /* test performance */
    printf("testing seed generation performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_create_seed(seed);
    }
    end = clock();

    printf("%fus per seed\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);


    printf("testing key generation performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_create_keypair(public_key, private_key, seed);
    }
    end = clock();

    printf("%fus per keypair\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

    printf("testing sign performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_sign(signature, message, message_len, public_key, private_key);
    }
    end = clock();

    printf("%fus per signature\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

    printf("testing verify performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_verify(signature, message, message_len, public_key);
    }
    end = clock();

    printf("%fus per signature\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);


    printf("testing keypair scalar addition performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_add_scalar(public_key, private_key, scalar);
    }
    end = clock();

    printf("%fus per keypair\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

    printf("testing public key scalar addition performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_add_scalar(public_key, NULL, scalar);
    }
    end = clock();

    printf("%fus per key\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

    printf("testing key exchange performance: ");
    start = clock();
    for (i = 0; i < 10000; ++i) {
        ed25519_key_exchange(shared_secret, other_public_key, private_key);
    }
    end = clock();

    printf("%fus per shared secret\n", ((double) ((end - start) * 1000)) / CLOCKS_PER_SEC / i * 1000);

}
void test2(){
    unsigned char signature[64];

    const unsigned char message[] = "Hello";
    const int message_len = strlen((char*) message);
    unsigned char seed[32] = {0xe5,0x99,0x64,0x06,0x7f,0x8d,0xa7,0x72,0xaa,0x66,0xdb,0x8b,0xb4,0xc9,0x90,0x10,0x32,0x03,0xfe,0xcc,0xce,0x3c,0xf7,0xe2,0x4b,0x38,0xda,0x82,0xc4,0x31,0x00,0xf5};

    unsigned char private_key[64], public_key[32];

    ed25519_create_keypair(public_key,private_key,seed);

    printf("Public Key: ");
    printCharInHexadecimal(public_key,32);

    printf("Private Key: ");
    printCharInHexadecimal(private_key,64);

    printf("Message: ");
    printCharInHexadecimal(message,message_len);

    ed25519_sign(signature, message, message_len, public_key, private_key);

    printf("Message Signature: ");
    printCharInHexadecimal(signature, 64);

}

int main() {
    test2();
}
