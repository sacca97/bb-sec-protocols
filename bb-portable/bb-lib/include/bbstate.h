#include <stddef.h>
#include <stdint.h>
#include "crypto.h"

#define MESSAGE_INVALID 0

#define BB_PAIR_REQ 1
#define BB_PAIR_RSP 2
#define BB_PAIR_PUB_KEY 3

#define BB_SESSION_START_REQ 6
#define BB_SESSION_START_RSP 7

#define BB_ROLE_CENTRAL 0
#define BB_ROLE_PERIPHERAL 1

struct bbstate_s {
    uint8_t static_public_key[KEY_LEN];
    uint8_t static_private_key[KEY_LEN];

    uint8_t ephmeral_public_key[KEY_LEN];
    uint8_t ephmeral_private_key[KEY_LEN];

    uint8_t rs[KEY_LEN];  /* Remote static public key */
    uint8_t re[KEY_LEN];  /* Remote ephemeral public key */
    uint8_t psk[KEY_LEN]; /* Optional pre-shared key */

    uint8_t hc[32]; /* Handshake hash transcript */

    uint8_t role;         /* Central or Peripheral */
    uint64_t counter;     /* Message counter*/
    uint8_t key[KEY_LEN]; /* Encryption key */
};

typedef struct bbstate_s bbstate;

struct bb_session_start_req {
    uint8_t type;
    uint8_t reserved[3];
    uint8_t ephemeral[KEY_LEN];
    uint64_t counter;
    uint8_t auth[TAG_LEN];
} __attribute__((__packed__));

// TODO: update with latest paper changes
struct bb_pair_req {
    uint8_t type;
    uint8_t iocap;
    uint8_t oob;
    uint8_t reserved[4];
    uint64_t counter;

    uint8_t ephemeral[KEY_LEN];
    uint8_t auth[TAG_LEN];
} __attribute__((__packed__));

struct bb_pair_pubkey {
    uint8_t type;
    uint64_t counter;
    uint8_t key[KEY_LEN];
    uint8_t auth[TAG_LEN];
} __attribute__((__packed__));

void
bbstate_init(bbstate* st, int role, uint8_t* s_pub, uint8_t* s_priv,
             uint8_t* rs, uint8_t* psk);

void
bb_session_start_req(bbstate* st, uint8_t* msgbuf);

void
bb_session_start_rsp(bbstate* st, uint8_t* msgbuf);

void
bb_session_start_rx(bbstate* st, uint8_t* msgbuf);

void
bb_pair_rsp_rx(bbstate* st, uint8_t* msgbuf);
void
bb_pair_req_rx(bbstate* st, uint8_t* msgbuf);
void
bb_pair_req_build(bbstate* st, uint8_t* msgbuf);

void
bb_pair_pubkey_build(bbstate* st, uint8_t* msgbuf);

void
bb_pair_pubkey_rx(bbstate* st, uint8_t* msgbuf);