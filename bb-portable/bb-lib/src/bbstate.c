#include "bbstate.h"
#include <string.h>
#include "crypto/blake2.h"
#include <stdio.h>

void print_buf(void *buf, size_t buf_len)
{
    uint8_t *bufr = (uint8_t *)buf;
    for (int i = 0; i < buf_len; i++)
    {
        printf("%02x", bufr[i]);
    }
    printf("\n");
}

void mixhash(bbstate *st, const uint8_t *src, size_t src_len)
{
    blake2b_state ctx;
    blake2b_init(&ctx, HASH_LEN);
    blake2b_update(&ctx, st->hc, HASH_LEN);
    blake2b_update(&ctx, src, src_len);
    blake2b_final(&ctx, st->hc, HASH_LEN);
}

void bbstate_init(bbstate *st, int role, uint8_t *s_pub, uint8_t *s_priv,
                  uint8_t *rs, uint8_t *psk)
{
    st->role = role;
    st->counter = 0;

    // I should zero the whole state
    memset(st->hc, 0, sizeof(st->hc));

    if (s_pub && s_priv)
    {
        memcpy(st->static_public_key, s_pub, KEY_LEN);
        memcpy(st->static_private_key, s_priv, KEY_LEN);
    }

    // BB-session assumes both possess remote static keys
    if (rs)
    {
        memcpy(st->rs, rs, KEY_LEN);
        if (role == 0)
        {
            mixhash(st, st->rs, KEY_LEN);
            mixhash(st, st->static_public_key, KEY_LEN);
        }
        else
        {
            mixhash(st, st->static_public_key, KEY_LEN);
            mixhash(st, st->rs, KEY_LEN);
        }
    }

    if (psk)
        memcpy(st->psk, psk, KEY_LEN);

    // Initialize handshake hash chain
    uint8_t init_hash[] = "bb-portable_handshake_application_level";
    mixhash(st, init_hash, sizeof(init_hash));
}

void bb_pairing_req_build(bbstate *st, uint8_t *msgbuf)
{
    struct bb_session_start_req *msg = (struct bb_session_start_req *)msgbuf;
    memset(msg->reserved, 0, sizeof(msg->reserved));
    msg->counter = st->counter;

    ecdh_keygen(st->ephmeral_public_key, st->ephmeral_private_key);
    memcpy(msg->ephemeral, st->ephmeral_public_key, KEY_LEN);
    mixhash(st, st->ephmeral_public_key, KEY_LEN);
    memset(msg->auth, 0, sizeof(msg->auth));
}

void bb_session_start_build(bbstate *st, struct bb_session_start_req *msg)
{
    memset(msg->reserved, 0, sizeof(msg->reserved));
    msg->counter = st->counter;

    ecdh_keygen(st->ephmeral_public_key, st->ephmeral_private_key);
    memcpy(msg->ephemeral, st->ephmeral_public_key, KEY_LEN);
    mixhash(st, st->ephmeral_public_key, KEY_LEN);

    ecdh_make_shared(st->key, st->rs, st->ephmeral_private_key);

    hkdf(st->key, NULL, NULL, st->key, st->hc, sizeof(st->hc));

    aead_encrypt(msg->auth, st->key, st->counter, st->hc, sizeof(st->hc), NULL,
                 0);
    mixhash(st, &msg->type, sizeof(*msg));
}

void bb_session_start_req(bbstate *st, uint8_t *msgbuf)
{
    struct bb_session_start_req *msg = (struct bb_session_start_req *)msgbuf;
    msg->type = BB_SESSION_START_REQ;
    bb_session_start_build(st, msg);
}

void bb_session_start_rsp(bbstate *st, uint8_t *msgbuf)
{
    struct bb_session_start_req *msg = (struct bb_session_start_req *)msgbuf;
    msg->type = BB_SESSION_START_RSP;
    bb_session_start_build(st, msg);
}

// Processing is symmetric
void bb_session_start_rx(bbstate *st, uint8_t *msgbuf)
{
    struct bb_session_start_req *msg = (struct bb_session_start_req *)msgbuf;

    memcpy(st->re, msg->ephemeral, KEY_LEN);
    mixhash(st, st->re, KEY_LEN);

    ecdh_make_shared(st->key, st->re, st->static_private_key);

    hkdf(st->key, NULL, NULL, st->key, st->hc, sizeof(st->hc));

    aead_decrypt(NULL, st->key, msg->counter, st->hc, sizeof(st->hc), msg->auth,
                 TAG_LEN);

    mixhash(st, &msg->type, sizeof(*msg));
    // TOD): if decrypt fails means auth failed here we abort

    // else do this
    if (msg->counter < st->counter)
    {
        // Counter is too old, ignore the message
        return;
    }
    // Otherwise counter was already updated in the decrypt function
}

void bb_pair_req_build(bbstate *st, uint8_t *msgbuf)
{
    struct bb_pair_req *msg = (struct bb_pair_req *)msgbuf;
    memset(msg->reserved, 0, sizeof(msg->reserved));
    msg->type = BB_PAIR_REQ;
    msg->iocap = 0; // TODO: Set IO capabilities
    msg->oob = 0;   // TODO: Set OOB data if available
    memset(msg->auth, 0, sizeof(msg->auth));

    msg->counter = st->counter;

    ecdh_keygen(st->ephmeral_public_key, st->ephmeral_private_key);
    memcpy(msg->ephemeral, st->ephmeral_public_key, KEY_LEN);
    mixhash(st, st->ephmeral_public_key, KEY_LEN);
    mixhash(st, &msg->type, sizeof(*msg));
}

// also sends the rsp
void bb_pair_req_rx(bbstate *st, uint8_t *msgbuf)
{
    struct bb_pair_req *msg = (struct bb_pair_req *)msgbuf;

    if (msg->counter < st->counter)
    {
        // Counter is too old, ignore the message
        return;
    }
    st->counter = msg->counter + 1;

    // msg->iocap = 0; // TODO: do something with IO capabilities
    // msg->oob = 0;   // TODO: do something with OOB

    memcpy(st->re, msg->ephemeral, KEY_LEN);
    mixhash(st, st->re, KEY_LEN);
    mixhash(st, &msg->type, sizeof(*msg));

    msg->counter = st->counter;

    ecdh_keygen(st->ephmeral_public_key, st->ephmeral_private_key);
    ecdh_make_shared(st->key, msg->ephemeral, st->ephmeral_private_key);

    hkdf(st->key, NULL, NULL, st->key, st->hc, sizeof(st->hc));
    print_buf(st->key, sizeof(st->key));

    memcpy(msg->ephemeral, st->ephmeral_public_key, KEY_LEN);
    mixhash(st, st->ephmeral_public_key, KEY_LEN);

    aead_encrypt(msg->auth, st->key, st->counter, st->hc, sizeof(st->hc), NULL,
                 0);

    mixhash(st, &msg->type, sizeof(*msg));
    print_buf(st->hc, sizeof(st->hc));
}

void bb_pair_rsp_rx(bbstate *st, uint8_t *msgbuf)
{
    struct bb_pair_req *msg = (struct bb_pair_req *)msgbuf;

    if (msg->counter < st->counter)
    {
        // Counter is too old, ignore the message
        return;
    }
    st->counter = msg->counter + 1;

    memcpy(st->re, msg->ephemeral, KEY_LEN);
    ecdh_make_shared(st->key, st->re, st->ephmeral_private_key);
    hkdf(st->key, NULL, NULL, st->key, st->hc, sizeof(st->hc));

    mixhash(st, st->re, KEY_LEN);

    aead_decrypt(NULL, st->key, msg->counter, st->hc, sizeof(st->hc), msg->auth,
                 sizeof(msg->auth));

    mixhash(st, &msg->type, sizeof(*msg));
}