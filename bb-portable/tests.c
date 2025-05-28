#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bbstate.h"

static bbstate central, peripheral;

static uint8_t pub_c[32];
static uint8_t priv_c[32];

static uint8_t pub_p[32];
static uint8_t priv_p[32];

void print_buf(void *buf, size_t buf_len)
{
    uint8_t *bufr = (uint8_t *)buf;
    for (int i = 0; i < buf_len; i++)
    {
        printf("%02x", bufr[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{

    uint8_t buffer[128];

    uint8_t shared_c[32];
    uint8_t shared_p[32];

    // BB-session

    for (int i = 0; i < 10; i++)
    {
        ecdh_keygen(pub_c, priv_c);
        ecdh_keygen(pub_p, priv_p);

        bbstate_init(&central, BB_ROLE_CENTRAL, pub_c, priv_c, pub_p, NULL);
        bbstate_init(&peripheral, BB_ROLE_PERIPHERAL, pub_p, priv_p, pub_c,
                     NULL);

        // assert(memcmp(central.hc, peripheral.hc, sizeof(central.hc)) == 0);

        bb_session_start_req(&central, buffer);

        bb_session_start_rx(&peripheral, buffer);

        bb_session_start_rsp(&peripheral, buffer);

        bb_session_start_rx(&central, buffer);

        assert(memcmp(central.key, peripheral.key, sizeof(central.key)) == 0);
        assert(memcmp(central.hc, peripheral.hc, sizeof(central.hc)) == 0);
        memset(&central, 0, sizeof(central));
        memset(&peripheral, 0, sizeof(peripheral));
    }

    ecdh_keygen(pub_c, priv_c);
    ecdh_keygen(pub_p, priv_p);

    bbstate_init(&central, BB_ROLE_CENTRAL, pub_c, priv_c, NULL, NULL);
    bbstate_init(&peripheral, BB_ROLE_PERIPHERAL, pub_p, priv_p, NULL,
                 NULL);

    // print_buf(central.hc, 32);
    // print_buf(peripheral.hc, 32);

    // assert(memcmp(central.hc, peripheral.hc, sizeof(central.hc)) == 0);

    bb_pair_req_build(&central, buffer);

    bb_pair_req_rx(&peripheral, buffer);

    bb_pair_rsp_rx(&central, buffer);

    // OK
}