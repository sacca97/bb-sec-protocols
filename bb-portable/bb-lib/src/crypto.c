#include "crypto.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "crypto/blake2.h"
#include "crypto/chachapoly.h"
#include "crypto/ecdh/curve25519.h"

void
random_buf(uint8_t* buf, size_t buf_len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    ssize_t olen = read(fd, buf, buf_len);
    if (olen != buf_len) {
        printf("Error reading from /dev/urandom\n");
    }
    close(fd);
}

size_t
aead_encrypt(uint8_t* out, uint8_t* key, uint64_t nonce, const uint8_t* ad,
             size_t ad_len, const uint8_t* in, size_t in_len)
{
    uint8_t n[NONCE_LEN] = {0};
    PUT_UINT64(n + 4, nonce);
    size_t rc =
        portable_chacha20_poly1305_encrypt(out, key, n, ad, ad_len, in, in_len);
    nonce++;
    return rc;
}

size_t
aead_decrypt(uint8_t* out, uint8_t* key, uint64_t nonce, const uint8_t* ad,
             size_t ad_len, const uint8_t* in, size_t in_len)
{
    uint8_t n[NONCE_LEN] = {0};
    PUT_UINT64(n + 4, nonce);
    size_t rc =
        portable_chacha20_poly1305_decrypt(out, key, n, ad, ad_len, in, in_len);
    nonce++;
    return rc;
}

void
hmac(uint8_t* out, const uint8_t* key, size_t key_len, const uint8_t* data,
     size_t data_len)
{
    blake2b_state ctx;
    blake2b_init_key(&ctx, HASH_LEN, key, key_len);
    blake2b_update(&ctx, data, data_len);
    blake2b_final(&ctx, out, HASH_LEN);

    // TODO: use ascon also
}

void
crypto_zero(void* dest, size_t size)
{
    volatile uint8_t* p = (volatile uint8_t*)dest;
    while (size--) {
        *p++ = 0;
    }
}

void
hkdf(uint8_t* tau1, uint8_t* tau2, uint8_t* tau3, const uint8_t* key,
     const uint8_t* data, size_t data_len)
{
    uint8_t prk[HASH_LEN];
    uint8_t prev[HASH_LEN];
    uint8_t tmp[HASH_LEN + 1];
    uint8_t info[] = "bluebrothersprotocols";

    hmac(prk, key, KEY_LEN, data, data_len);

    memcpy(tmp, info, sizeof(info));
    tmp[sizeof(info)] = 1;

    hmac(prev, prk, sizeof(prk), tmp, sizeof(info) + 1);
    memcpy(tau1, prev, HASH_LEN);

    // if (tau2) {
    //     // tau2 := Hmac(tau0, tau1 || 0x2)
    //     output[HASH_LEN] = 2;
    //     hmac(output, tau0, HASH_LEN, output, HASH_LEN + 1);
    //     memcpy(tau2, output, HASH_LEN);
    // }

    // if (tau3) {
    //     // tau3 := Hmac(tau0, tau2 || 0x3)
    //     output[HASH_LEN] = 3;
    //     hmac(output, tau0, HASH_LEN, output, HASH_LEN + 1);
    //     memcpy(tau3, output, HASH_LEN);
    // }

    // // Wipe intermediates
    // crypto_zero(tau0, sizeof(tau0));
    // crypto_zero(output, sizeof(output));
}

void
ecdh_keygen(uint8_t* public, uint8_t* private)
{
    random_buf(private, KEY_LEN);
    curve25519_clamp_privatekey(private);
    curve25519_gen_publickey(public, private);
}

void
ecdh_make_shared(uint8_t* shared, uint8_t* public, uint8_t* private)
{
    curve25519_gen_sharedkey(shared, private, public);
}