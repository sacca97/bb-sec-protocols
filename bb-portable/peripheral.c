#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include "bbstate.h"
#include <bluetooth/hci.h>     // For HCI functions
#include <bluetooth/hci_lib.h> // For HCI functions

/* server channel */
#define L2CAP_SERVER_PORT_NUM 0x0235

static uint8_t private_key[32] = {0x60, 0x58, 0xce, 0x93, 0x0d, 0xf3, 0xdd, 0x2e, 0xa0, 0x0e, 0x1a, 0x62, 0x6b, 0xc7, 0x0b, 0xa4, 0x17, 0x74, 0xea, 0x11, 0xe9, 0xa2, 0xef, 0x28, 0x7e, 0xd2, 0x5a, 0x59, 0xca, 0x04, 0x03, 0x6b};
static uint8_t public_key[32] = {0x49, 0x5a, 0xfa, 0xd7, 0xaf, 0x39, 0xae, 0x9f, 0x18, 0xdb, 0x1a, 0x69, 0xd6, 0x88, 0xe3, 0xd2, 0x4a, 0xa1, 0xec, 0xa5, 0x49, 0xac, 0x95, 0xc0, 0x46, 0x80, 0x3d, 0x22, 0x03, 0x59, 0x65, 0x73};
static uint8_t remote_public_key[32] = {0x76, 0x8a, 0x58, 0x2e, 0x1f, 0x44, 0x21, 0xc9, 0xb7, 0x55, 0xf3, 0x70, 0xdf, 0xe9, 0x44, 0x98, 0x5f, 0x31, 0xe9, 0x54, 0x77, 0x7e, 0xb9, 0xba, 0xd6, 0x3d, 0xa0, 0xec, 0xf7, 0x4f, 0x6f, 0x61};

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
    unsigned int opt = sizeof(rem_addr);

    bdaddr_t local_bdaddr = {0}; // To store the hci1 address
    int dev_id = 1;              // hci1 device ID (change to 1 for hci1)

    printf("Start Bluetooth L2CAP server...\n");

    /* Get the local Bluetooth address of hci1 */
    int hci_sock = hci_open_dev(dev_id);
    if (hci_sock < 0)
    {
        perror("failed to open HCI device hci1");
        exit(1);
    }

    if (hci_read_bd_addr(hci_sock, &local_bdaddr, 0) < 0)
    {
        perror("failed to read local Bluetooth address for hci1");
        close(hci_sock);
        exit(1);
    }

    char local_addr_str[18];
    ba2str(&local_bdaddr, local_addr_str);
    printf("Using local HCI device: hci%d (%s)\n", dev_id, local_addr_str);

    // uint16_t opcode = htobs(OGF_HOST_CTL | OCF_WRITE_SCAN_ENABLE); // OGF_HOST_CTL (3 << 10) | 0x1A
    uint8_t param = (SCAN_PAGE | SCAN_INQUIRY); // 0x03 for Inquiry and Page Scan

    // Send the HCI command
    // hci_send_cmd(dd, opcode, param_len, param_data)
    if (hci_send_cmd(hci_sock, OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE, 1, &param) < 0)
    {
        perror("Failed to send HCI_Write_Scan_Enable command");
        return -1;
    }
    close(hci_sock);

    /* allocate socket */
    server_socket = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (server_socket < 0)
    {
        perror("failed to create socket");
        exit(1);
    }

    /* bind socket to the local bluetooth adapter (hci1) */
    loc_addr.l2_family = AF_BLUETOOTH;              /* Addressing family, always AF_BLUETOOTH */
    bacpy(&loc_addr.l2_bdaddr, &local_bdaddr);      /* Bluetooth address of hci1 */
    loc_addr.l2_psm = htobs(L2CAP_SERVER_PORT_NUM); /* port number of local bluetooth adapter */

    printf("binding\n");
    if (bind(server_socket, (struct sockaddr *)&loc_addr, sizeof(loc_addr)) < 0)
    {
        perror("failed to bind");
        close(server_socket);
        exit(1);
    }

    printf("listening\n");
    /* put socket into listening mode */
    listen(server_socket, 2);
    /* accept one connection */
    client_socket = accept(server_socket, (struct sockaddr *)&rem_addr, &opt); /* return new socket for connection with a client */
    if (client_socket < 0)
    {
        perror("accept");
        close(server_socket);
        return client_socket;
    }
    char buf[18];
    ba2str(&rem_addr.l2_bdaddr, buf);
    printf("connected from %s\n", buf);

    bbstate_init(&state, BB_ROLE_PERIPHERAL, public_key, private_key, remote_public_key, NULL);

    /* read data from the client */
    bytes_read = recv(client_socket, buffer, sizeof(struct bb_session_start_req), 0);
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
    int rc = send(client_socket, buffer, sizeof(struct bb_session_start_req), 0);
    if (rc <= 0)
    {
        perror("Error sending");
        close(client_socket);
        close(server_socket);
        exit(1);
    }
    printf("Handshake complete, key:\n");
    print_buf(state.key, 32);
    /* close connection */
    close(client_socket);
    close(server_socket);
    return 0;
}