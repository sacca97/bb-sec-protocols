#ifndef __ecc25519_donna_h__
#define __ecc25519_donna_h__

#ifdef __cplusplus
extern "C" {
#endif

#include "basetypes.h"

typedef S64 felem;

void
curve25519_donna(uint8_t* donna_publickey, const uint8_t* secret,
                 const uint8_t* basepoint);

void
curve25519_clamp_privatekey(uint8_t* secret);

void
curve25519_gen_privatekey(uint8_t* secret);

void
curve25519_gen_publickey(uint8_t* publickey, const uint8_t* secret);
void
curve25519_gen_sharedkey(uint8_t* sharedkey, const uint8_t* secret,
                         const uint8_t* publickey);

#ifdef __cplusplus
}
#endif
#endif /* __ecc25519_donna_h__ */