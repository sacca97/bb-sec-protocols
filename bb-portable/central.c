#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include "bbstate.h"
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
// #include "bluetooth/hci_lib.h"

#define L2CAP_SERVER_PORT_NUM 0x0235

static uint8_t private_key[32] = {
    0x00, 0xee, 0x2a, 0xfc, 0x36, 0xe9, 0x58, 0xdf, 0x08, 0x94, 0x3b,
    0xc9, 0x96, 0x88, 0x3a, 0x44, 0x2c, 0x0b, 0xc5, 0x40, 0x41, 0x0d,
    0x40, 0x0a, 0x1e, 0x38, 0x27, 0x22, 0x1e, 0x0f, 0x26, 0x4e};
static uint8_t public_key[32] = {
    0x76, 0x8a, 0x58, 0x2e, 0x1f, 0x44, 0x21, 0xc9, 0xb7, 0x55, 0xf3,
    0x70, 0xdf, 0xe9, 0x44, 0x98, 0x5f, 0x31, 0xe9, 0x54, 0x77, 0x7e,
    0xb9, 0xba, 0xd6, 0x3d, 0xa0, 0xec, 0xf7, 0x4f, 0x6f, 0x61};
static uint8_t remote_public_key[32] = {
    0x49, 0x5a, 0xfa, 0xd7, 0xaf, 0x39, 0xae, 0x9f, 0x18, 0xdb, 0x1a,
    0x69, 0xd6, 0x88, 0xe3, 0xd2, 0x4a, 0xa1, 0xec, 0xa5, 0x49, 0xac,
    0x95, 0xc0, 0x46, 0x80, 0x3d, 0x22, 0x03, 0x59, 0x65, 0x73};

static bbstate state;

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
    struct sockaddr_l2 loc_addr = {0};
    struct sockaddr_l2 rem_addr = {0};
    int sock, status;
    uint8_t buffer[128];
    char dest_addr_str[18] = {0};
    int dev_id = -1;
    int c;

    static struct option long_options[] = {
        {"dev", required_argument, 0, 'd'},
        {0, 0, 0, 0}};

    while (1)
    {
        int option_index = 0;
        c = getopt_long(argc, argv, "d:", long_options, &option_index);

        if (c == -1)
            break;

        switch (c)
        {
        case 'd':
            dev_id = atoi(optarg);
            break;
        case '?':
            break;
        default:
            if (optind <= argc)
            {
                strncpy(dest_addr_str, argv[optind - 1], 17);
                dest_addr_str[17] = '\0';
            }
        }
    }

    if (dest_addr_str[0] == 0)
    {
        if (optind < argc)
        {
            strncpy(dest_addr_str, argv[optind], 17);
            dest_addr_str[17] = '\0';
        }
        else
        {
            fprintf(stderr, "Usage: %s <Bluetooth Address> [--dev <device>]\n", argv[0]);
            exit(1);
        }
    }

    printf("Starting Bluetooth L2CAP client...\n");

    /* allocate a socket */
    sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (sock < 0)
    {
        perror("failed to create socket");
        exit(1);
    }

    /* bind socket to a specific local adapter */
    if (dev_id >= 0)
    {
        loc_addr.l2_family = AF_BLUETOOTH;
        hci_devba(dev_id, &loc_addr.l2_bdaddr);

        if (bind(sock, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0)
        {
            perror("failed to bind socket");
            close(sock);
            exit(1);
        }
    }

    /* set the connection parameters (who to connect to) */
    rem_addr.l2_family = AF_BLUETOOTH;
    rem_addr.l2_psm = htobs(L2CAP_SERVER_PORT_NUM);
    if (str2ba(dest_addr_str, &rem_addr.l2_bdaddr) < 0)
    {
        perror("str2ba failed to parse address");
        exit(1);
    }

    int security_level = BT_SECURITY_LOW;
    int err = setsockopt(sock, SOL_BLUETOOTH, BT_SECURITY, &security_level, sizeof(security_level));
    if (err != 0)
    {
        perror("setsockopt(BT_SECURITY) failed");
    }

    printf("Connecting to %s on PSM 0x%04X...\n", dest_addr_str, L2CAP_SERVER_PORT_NUM);

    /* connect to server */
    // The connect() call handles everything: creating the ACL link
    // and establishing the L2CAP channel. No hci_* calls or client-side
    // bind() are necessary.
    status = connect(sock, (struct sockaddr *)&rem_addr, sizeof(rem_addr));
    if (status < 0)
    {
        perror("failed to connect. (Is server running and discoverable? Are you using sudo?)");
        close(sock);
        exit(1);
    }

    printf("Connected successfully!\n");

    bbstate_init(&state, BB_ROLE_CENTRAL, public_key, private_key,
                 remote_public_key, NULL);
    bb_session_start_req(&state, buffer);

    /* send data to server */
    if (send(sock, buffer, sizeof(struct bb_session_start_req), 0) <= 0)
    {
        perror("failed to send data");
        close(sock);
        exit(1);
    }

    if (recv(sock, buffer, sizeof(struct bb_session_start_req), 0) <= 0)
    {
        perror("failed to receive data");
        close(sock);
        exit(1);
    }
    bb_session_start_rx(&state, buffer);
    printf("Handshake complete, key:\n");
    print_buf(state.key, sizeof(state.key));

    /* Exchange data here, use:

    aead_encrypt and aead_decrypt (needs a counter as nonce)

    send and recv

    */

    close(sock);
    printf("Client finished.\n");
    return 0;
}