#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include "bbstate.h"
#include <bluetooth/hci.h>     // For HCI functions
#include <bluetooth/hci_lib.h> // For HCI functions

/* server channel */
#define L2CAP_SERVER_PORT_NUM 0x0235

static uint8_t private_key[32] = {
    0x60, 0x58, 0xce, 0x93, 0x0d, 0xf3, 0xdd, 0x2e, 0xa0, 0x0e, 0x1a,
    0x62, 0x6b, 0xc7, 0x0b, 0xa4, 0x17, 0x74, 0xea, 0x11, 0xe9, 0xa2,
    0xef, 0x28, 0x7e, 0xd2, 0x5a, 0x59, 0xca, 0x04, 0x03, 0x6b};
static uint8_t public_key[32] = {
    0x49, 0x5a, 0xfa, 0xd7, 0xaf, 0x39, 0xae, 0x9f, 0x18, 0xdb, 0x1a,
    0x69, 0xd6, 0x88, 0xe3, 0xd2, 0x4a, 0xa1, 0xec, 0xa5, 0x49, 0xac,
    0x95, 0xc0, 0x46, 0x80, 0x3d, 0x22, 0x03, 0x59, 0x65, 0x73};
static uint8_t remote_public_key[32] = {
    0x76, 0x8a, 0x58, 0x2e, 0x1f, 0x44, 0x21, 0xc9, 0xb7, 0x55, 0xf3,
    0x70, 0xdf, 0xe9, 0x44, 0x98, 0x5f, 0x31, 0xe9, 0x54, 0x77, 0x7e,
    0xb9, 0xba, 0xd6, 0x3d, 0xa0, 0xec, 0xf7, 0x4f, 0x6f, 0x61};

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
    struct sockaddr_l2 loc_addr = {0}, rem_addr = {0};
    uint8_t buffer[128] = {0};
    int server_socket, client_socket, bytes_read;
    socklen_t opt = sizeof(rem_addr);
    int err;
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
            fprintf(stderr, "Usage: %s [--dev <device>]\n", argv[0]);
            exit(1);
        default:
            break;
        }
    }

    err = system("bluetoothctl power on");
    if (err != 0)
    {
        perror("Failed to turn on Bluetooth power. Make sure you have permissions.");
        exit(1);
    }

    err = system("bluetoothctl discoverable on");
    if (err != 0)
    {
        perror("Failed to make Bluetooth discoverable. Make sure you have permissions.");
        exit(1);
    }

    err = system("bluetoothctl pairable on");
    if (err != 0)
    {
        perror("Failed to make Bluetooth pairable. Make sure you have permissions.");
        exit(1);
    }

    printf("Start Bluetooth L2CAP server...\n");
    printf("IMPORTANT: Make sure adapter is discoverable via 'bluetoothctl'\n");

    /* allocate socket */
    server_socket = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (server_socket < 0)
    {
        perror("failed to create socket");
        exit(1);
    }

    /* bind socket to any local bluetooth adapter */
    loc_addr.l2_family = AF_BLUETOOTH;
    if (dev_id >= 0)
    {
        hci_devba(dev_id, &loc_addr.l2_bdaddr);
    }
    else
    {
        bacpy(&loc_addr.l2_bdaddr, BDADDR_ANY);
    }
    loc_addr.l2_psm = htobs(L2CAP_SERVER_PORT_NUM);

    printf("Binding to PSM 0x%04X\n", L2CAP_SERVER_PORT_NUM);
    if (bind(server_socket, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0)
    {
        perror("failed to bind. (Are you running with sudo?)");
        close(server_socket);
        exit(1);
    }

    // Note: Security settings like BT_SECURITY might require a paired device
    // for higher security levels. LOW is generally fine for initial connection.
    int security_level = BT_SECURITY_LOW;
    err = setsockopt(server_socket, SOL_BLUETOOTH, BT_SECURITY, &security_level, sizeof(security_level));
    if (err != 0)
    {
        perror("setsockopt(BT_SECURITY) failed");
        // This might not be a fatal error, so we can choose to continue
    }

    printf("Listening...\n");
    /* put socket into listening mode */
    if (listen(server_socket, 1) < 0)
    {
        perror("listen failed");
        close(server_socket);
        exit(1);
    }

    /* accept one connection */
    client_socket = accept(server_socket, (struct sockaddr *)&rem_addr, &opt);
    if (client_socket < 0)
    {
        perror("accept failed");
        close(server_socket);
        exit(1);
    }

    char rem_addr_str[18];
    ba2str(&rem_addr.l2_bdaddr, rem_addr_str);
    printf("Accepted connection from %s\n", rem_addr_str);

    // ... (The rest of your handshake logic is likely fine) ...
    bbstate_init(&state, BB_ROLE_PERIPHERAL, public_key, private_key,
                 remote_public_key, NULL);

    /* read data from the client */
    bytes_read =
        recv(client_socket, buffer, sizeof(struct bb_session_start_req), 0);
    if (bytes_read <= 0)
    {
        perror("Error handshake initiation\n");
        close(client_socket);
        close(server_socket);
        exit(1);
    }

    // Process the received handshake request
    bb_session_start_rx(&state, buffer);

    // Prepare the response
    bb_session_start_rsp(&state, buffer);

    // Send response
    int rc =
        send(client_socket, buffer, sizeof(struct bb_session_start_req), 0);
    if (rc <= 0)
    {
        perror("Error sending");
        close(client_socket);
        close(server_socket);
        exit(1);
    }
    printf("Handshake complete, key:\n");
    print_buf(state.key, 32);

    /* Exchange data here, use:

    aead_encrypt and aead_decrypt (needs a counter as nonce)

    send and recv

    */

    /* close connection */
    close(client_socket);
    close(server_socket);

    system("bluetoothctl default-agent");
    system("hciconfig hci0 auth");

    printf("Server finished.\n");
    return 0;
}