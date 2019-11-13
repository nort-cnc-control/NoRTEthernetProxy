
/*
NoRT Ethernet Sender
Copyright (C) 2019  Vladislav Tsendrovskii

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
Program description:

This program is designed for transmitting lines to Ethernet, each line in it's own Ethernet frame,
and receive frames from Ethernet and send them as line.

Ethertype = 0xFEFE
Frame format: hightbyte:lowbyte:string_without_'\n'
Line shouldn't be longer than 1498 bytes.

Lines are received and transmitted from/to TCP:8889

When frame with ethertype = 0xFEFE is received, it's source is remembered and next frames are sending to this address.
Until this, frames are sended to broadcast address.

How to run:

nort_eth_proxy if_name

where if_name is a Ethernet interface name. eth0 as default
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include <arpa/inet.h>

#define ETHERTYPE 0xFEFE

int readline(int sock, char *buf)
{
    int i = 0;
    char c;
    do
    {
        int res = recv(sock, &c, 1, 0);
        if (res <= 0)
        {
            return -1;
        }
        if (c != '\n')
            buf[i++] = c;
    } while (c != '\n');
    buf[i++] = 0;
    return i-1;
}

int sendline(int sock, const char *buf, size_t len)
{
    const char cr = '\n';
    send(sock, buf, len, 0);
    send(sock, &cr, 1, 0);
    return len + 1;
}

struct sockaddr_ll eth_sockaddr;
unsigned char remote[ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
unsigned char local[ETH_ALEN];

int send_command_to_rt(int ethsock, const char *buf, size_t len)
{
    char ebuf[1500];
    struct ether_header *eh = (struct ether_header *)ebuf;
    size_t msglen = 0;
   
    eh->ether_shost[0] = local[0];
    eh->ether_shost[1] = local[1];
    eh->ether_shost[2] = local[2];
    eh->ether_shost[3] = local[3];
    eh->ether_shost[4] = local[4];
    eh->ether_shost[5] = local[5];

    eh->ether_dhost[0] = remote[0];
    eh->ether_dhost[1] = remote[1];
    eh->ether_dhost[2] = remote[2];
    eh->ether_dhost[3] = remote[3];
    eh->ether_dhost[4] = remote[4];
    eh->ether_dhost[5] = remote[5];

    eh->ether_type = htons(ETHERTYPE);
    msglen += sizeof(struct ether_header);

    ebuf[msglen++] = len / 256;
    ebuf[msglen++] = len % 256;

    memcpy(ebuf + msglen, buf, len);
    msglen += len;
    printf("Send to ethernet\n");
    return sendto(ethsock, ebuf, msglen, 0, (struct sockaddr *)&eth_sockaddr, sizeof(struct sockaddr_ll));
}

int recv_message_from_rt(int ethsock, char *buf, size_t maxlen)
{
    int len = recv(ethsock, buf, maxlen, 0);
    if (buf[12] != 0xFE || buf[13] != 0xFE)
        return -1;
    memcpy(remote, buf + 6, 6);
    int mlen = buf[14] * 256 + buf[15];
    memmove(buf, buf + 16, mlen);
    return mlen;
}

volatile int run;
int ethsock;
int ctlsock;

void print_hwaddr(const unsigned char *mac)
{
    int i;
    for (i = 0; i < ETH_ALEN; ++i)
    {
        if (i > 0)
            printf(":");
        printf("%02X", (int)(mac[i]));
    }
}

int get_iface_hwaddr(int sock, const char *ifname, unsigned char *addr)
{
    struct ifreq if_mac;
    memset(&if_mac, 0, sizeof(struct ifreq));
    strncpy(if_mac.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0)
    {
        perror("SIOCGIFHWADDR");
        return -1;
    }
    memcpy(addr, ((uint8_t *)&if_mac.ifr_hwaddr.sa_data), ETH_ALEN);
    return 0;
}

int get_iface_index(int sock, const char *ifname)
{
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, ifname, IFNAMSIZ-1);
    if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0)
    {
	    perror("SIOCGIFINDEX");
        return -1;
    }
    return if_idx.ifr_ifindex;
}

void* read_eth_socket_cycle(void *args)
{
    while (run)
    {
        char buf[1500];
        int len = recv_message_from_rt(ethsock, buf, 1500);
        if (len < 0)
            continue;
        printf("RECV ETH: %.*s\n", len, buf);
        sendline(ctlsock, buf, len);
    }
    return NULL;
}

int main(int argc, const char **argv)
{
    int port = 8889;
    int i;
    struct sockaddr_in ctl_sockaddr;
    const char* ifname = "eth0";
    if (argc > 1)
        ifname = argv[1];

    ethsock = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (ethsock < 0)
    {
        printf("Can not create Ethernet socket\n");
        return -2;
    }

    int index = get_iface_index(ethsock, ifname);
    if (index < 0)
        return -1;
    printf("Index = %i\n", index);
    if (get_iface_hwaddr(ethsock, ifname, local) < 0)
        return -1;
    printf("Local MAC address:\n");
    print_hwaddr(local);
    printf("\n");

    
    memset(&eth_sockaddr, 0, sizeof(struct sockaddr_ll));
    eth_sockaddr.sll_family = AF_PACKET;
    eth_sockaddr.sll_protocol = htons(ETHERTYPE);
    eth_sockaddr.sll_ifindex = index;
    eth_sockaddr.sll_halen = ETH_ALEN;
    eth_sockaddr.sll_hatype = 0x0001;

    if (bind(ethsock, (struct sockaddr *)&eth_sockaddr, sizeof(eth_sockaddr)) < 0)
    {
        printf("Can not bind to ethernet\n");
        return -1;
    }

    ctlsock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(ctlsock, SOL_SOCKET, SO_REUSEADDR, NULL, 0);

    ctl_sockaddr.sin_family = AF_INET;
    ctl_sockaddr.sin_port = htons(port);
    ctl_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(ctlsock, (struct sockaddr *)&ctl_sockaddr, sizeof(ctl_sockaddr)) < 0)
    {
        printf("Can not bind tcp\n");
        return -1;
    }
    run = 1;
    pthread_t thread;
    int res = pthread_create(&thread, NULL, read_eth_socket_cycle, NULL);

    listen(ctlsock, 1);
    while (1)
    {
        char buf[1500];
        int client = accept(ctlsock, NULL, NULL);
        printf("Connect from client\n");
        while (1)
        {
            int len = readline(client, buf);
            if (len < 0)
            {
                break;
            }
            printf("RECEIVE CTL: %.*s\n", len, buf);
            if (!strncmp(buf, "EXIT:", 5))
            {
                break;
            }
            else if (!strncmp(buf, "CMD:", 4))
            {
                const char *cmd = buf + 4;
                int res = send_command_to_rt(ethsock, cmd, len-4);
                printf("Send result: %i\n", res);
            }
        }
        printf("Client disconnected\n");
        close(client);
    }
    run = 0;
    pthread_join(thread, NULL);
    return 0;
}

