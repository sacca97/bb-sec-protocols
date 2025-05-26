#include <stdint.h>
#include <stddef.h>

#if PQDH_ENABLED
#define KEY_LEN -1 // Todo add kyber keylength
#else
#define KEY_LEN 32 // Default key length for Curve25519
#endif

#define HASH_LEN 32  // Length of the hash output
#define NONCE_LEN 12 // Length of the nonce used in AEAD
#define TAG_LEN 16

#define PUT_UINT64(buf, value)                                                 \
    do {                                                                       \
        (buf)[0] = (uint8_t)(value);                                           \
        (buf)[1] = (uint8_t)((value) >> 8);                                    \
        (buf)[2] = (uint8_t)((value) >> 16);                                   \
        (buf)[3] = (uint8_t)((value) >> 24);                                   \
        (buf)[4] = (uint8_t)((value) >> 32);                                   \
        (buf)[5] = (uint8_t)((value) >> 40);                                   \
        (buf)[6] = (uint8_t)((value) >> 48);                                   \
        (buf)[7] = (uint8_t)((value) >> 56);                                   \
    } while (0)

#define GET_UINT64(p)                                                          \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                        \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                 \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                 \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

size_t
aead_encrypt(uint8_t* out, uint8_t* key, uint64_t nonce, const uint8_t* ad,
             size_t ad_len, const uint8_t* in, size_t in_len);
size_t
aead_decrypt(uint8_t* out, uint8_t* key, uint64_t nonce, const uint8_t* ad,
             size_t ad_len, const uint8_t* in, size_t in_len);

void
hkdf(uint8_t* tau1, uint8_t* tau2, uint8_t* tau3, const uint8_t* key,
     const uint8_t* data, size_t data_len);

void
ecdh_keygen(uint8_t* public, uint8_t* private);

void
ecdh_make_shared(uint8_t* shared, uint8_t* public, uint8_t* private);

void
crypto_zero(void* dest, size_t size);