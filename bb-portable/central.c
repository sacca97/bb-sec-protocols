#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include "bbstate.h"
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
// #include "bluetooth/hci_lib.h"

#define L2CAP_SERVER_BLUETOOTH_ADDR                                            \
    "00:E0:4C:23:99:87" // Replace with your server's Bluetooth address
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

void
print_buf(void* buf, size_t buf_len)
{
    uint8_t* bufr = (uint8_t*)buf;
    for (int i = 0; i < buf_len; i++) {
        printf("%02x", bufr[i]);
    }
    printf("\n");
}

int
main(int argc, char** argv)
{
    uint8_t buffer[128];
    struct sockaddr_l2 addr = {0};
    int sock;
    const char* sample_text = "L2CAP Simple";
    bdaddr_t local_bdaddr = {0}; // To store the hci0 address
    int dev_id = 0;              // hci0 device ID

    printf("Start Bluetooth L2CAP client, server addr %s\n",
           L2CAP_SERVER_BLUETOOTH_ADDR);

    int hci_sock = hci_open_dev(dev_id);
    if (hci_sock < 0) {
        perror("failed to open HCI device");
        exit(1);
    }

    if (hci_read_bd_addr(hci_sock, &local_bdaddr, 0) < 0) {
        perror("failed to read local Bluetooth address");
        close(hci_sock);
        exit(1);
    }
    close(hci_sock);

    char local_addr_str[18];
    ba2str(&local_bdaddr, local_addr_str);
    printf("Using local HCI device: hci%d (%s)\n", dev_id, local_addr_str);

    /* allocate a socket */
    sock = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (sock < 0) {
        perror("failed to create socket");
        exit(1);
    }

    /* Set the local address for the client socket (hci0's address) */
    struct sockaddr_l2 local_addr = {0};
    local_addr.l2_family = AF_BLUETOOTH;
    bacpy(&local_addr.l2_bdaddr, &local_bdaddr); // Set to hci0's address

    if (bind(sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("failed to bind local socket");
        close(sock);
        exit(1);
    }

    /* set the outgoing connection parameters, server's address and port number */
    addr.l2_family = AF_BLUETOOTH; /* Addressing family, always AF_BLUETOOTH */
    addr.l2_psm = htobs(L2CAP_SERVER_PORT_NUM); /* server's port number */
    str2ba(L2CAP_SERVER_BLUETOOTH_ADDR,
           &addr.l2_bdaddr); /* server's Bluetooth Address */

    /* connect to server */
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("failed to connect");
        close(sock);
        exit(1);
    }

    printf("connected...\n");
    bbstate_init(&state, BB_ROLE_CENTRAL, public_key, private_key,
                 remote_public_key, NULL);
    bb_session_start_req(&state, buffer);

    /* send data to server */
    if (send(sock, buffer, sizeof(struct bb_session_start_req), 0) <= 0) {
        perror("failed to send data");
        close(sock);
        exit(1);
    }

    if (recv(sock, buffer, sizeof(struct bb_session_start_req), 0) <= 0) {
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
    return 0;
}