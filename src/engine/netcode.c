/*
 * Vivid Casino Engine — Network Module
 * 
 * Handles all client-server communication.
 * Implements a length-prefixed packet protocol for
 * reliable message delivery.
 */

#include "engine.h"

/* Initialize Windows networking */
int net_init(void) {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
}

/* Clean up networking */
void net_cleanup(void) {
    WSACleanup();
}

/* Send a length-prefixed packet */
int net_send_packet(SOCKET s, const char *data) {
    if (!data) return 0;
    int len = (int)strlen(data);
    char header[9];
    snprintf(header, sizeof(header), "%08d", len);
    if (send(s, header, 8, 0) != 8) return 0;
    return send(s, data, len, 0) == len;
}

/* Receive a length-prefixed packet */
char* net_recv_packet(SOCKET s) {
    static char buf[NET_BUF_SIZE];
    char hdr[9] = {0};
    int n, got = 0;
    
    while (got < 8) {
        n = recv(s, hdr + got, 8 - got, 0);
        if (n <= 0) return NULL;
        got += n;
    }
    
    int len = atoi(hdr);
    if (len <= 0 || len >= NET_BUF_SIZE - 1) return NULL;
    
    got = 0;
    while (got < len) {
        n = recv(s, buf + got, len - got, 0);
        if (n <= 0) return NULL;
        got += n;
    }
    buf[len] = '\0';
    return buf;
}

/* Receive packet with timeout */
char* net_recv_packet_timed(SOCKET s, int timeout_sec) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    struct timeval tv = {timeout_sec, 0};
    
    if (select(0, &fds, NULL, NULL, &tv) > 0 && FD_ISSET(s, &fds)) {
        return net_recv_packet(s);
    }
    return NULL;
}
