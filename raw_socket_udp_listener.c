#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
#include "SendARP.h"

#define DEST_UDP_PORT 9999
#define BUFFER_SIZE 1546 // This indicates maximum buffer size for the whole ethernet frame.


uint16_t checksum_udp(void *pseudo_buffer, int len)
{
    uint32_t sum = 0;
    uint16_t *buf = (uint16_t *)pseudo_buffer;
    
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    if (len == 1) {
        sum += *(uint8_t *)buf << 8;  // Pad the lower byte with zero
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)(~sum);
}

uint16_t checksum_ip(struct iphdr *ip)
{
    unsigned long sum = 0;
    uint16_t *ip_header = (uint16_t *)ip;

    /*IP header length is specified in 4-byte (32-bit) words, need to convert to 2-byte (16-bit) words*/
    int header_length = ip->ihl * 2;

    ip->check = 0;
    
    for (int i = 0; i < header_length; i++) {
        sum += *ip_header++;
    }
	
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return (uint16_t)(~sum);
}

void send_packet(const char *interface, const uint8_t *buffer, ssize_t length) {
    int sockfd;
    struct ifreq if_idx;
    struct sockaddr_ll socket_address;

    struct arp_header *mac_address;		
    struct pseudo_header pseudo_hdr;
    
    struct ether_header *eh = (struct ether_header *) buffer;
    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ether_header));
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
    const char *data = (const char *) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));

    /* Open RAW socket to send on */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
        perror("socket");
        exit(1);
    }

    /* Get the index of the interface to send on */
    memset(&if_idx, 0, sizeof(struct ifreq));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        exit(1);
    }

    /* Address */
    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    socket_address.sll_ifindex = if_idx.ifr_ifindex;
    socket_address.sll_halen = ETH_ALEN;
    
    /*ip change for dest*/
    iph->daddr = inet_addr("192.168.1.100");
    
    /*ip change for source*/
    iph->saddr = inet_addr("192.168.1.101");
    
    test_arping(interface, "192.168.1.100", &mac_address);
    
    
    /*MAC address change for source*/
    eh->ether_shost[0] = 0xb0;
    eh->ether_shost[1] = 0x25;
    eh->ether_shost[2] = 0xaa;
    eh->ether_shost[3] = 0x47;
    eh->ether_shost[4] = 0x9b;
    eh->ether_shost[5] = 0x9f;
    
    /*MAC address change for dest*/
    eh->ether_dhost[0] = mac_address->sender_mac[0];
    eh->ether_dhost[1] = mac_address->sender_mac[1];
    eh->ether_dhost[2] = mac_address->sender_mac[2];
    eh->ether_dhost[3] = mac_address->sender_mac[3];
    eh->ether_dhost[4] = mac_address->sender_mac[4];
    eh->ether_dhost[5] = mac_address->sender_mac[5];
    
    
    udp->dest = htons(9000);
    iph->check = checksum_ip(iph);
    
    int data_len = length - sizeof(struct ether_header) - sizeof(struct iphdr) - sizeof(struct udphdr);

    /*Create pseudo header*/
    pseudo_hdr.dest_address = iph->daddr;
    pseudo_hdr.source_address = iph->saddr;
    pseudo_hdr.protocol = 0x11;
    pseudo_hdr.placeholder = 0;
    pseudo_hdr.udp_length = htons(sizeof(struct udphdr) + data_len);
    
    udp->check = 0x0000; /*initially make checksum zero*/
    
    
    int ucheck_size = sizeof(struct pseudo_header) + sizeof(struct udphdr) + data_len;
    char *check_buffer = malloc(ucheck_size);

    memcpy(check_buffer, (char *) &pseudo_hdr, sizeof(struct pseudo_header));
    memcpy(check_buffer + sizeof(struct pseudo_header), udp, sizeof(struct udphdr));
    memcpy(check_buffer + sizeof(struct pseudo_header) + sizeof(struct udphdr), data, data_len);
    
    udp->check = checksum_udp(check_buffer,ucheck_size);

    free(check_buffer);

    /* Send packet */
    if (sendto(sockfd, buffer, length, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto");
        close(sockfd);
        exit(1);
    }   

    close(sockfd);
}


int main(int argc, char *argv[]) {
    
    char sender_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];
    struct sockaddr_in ip_address_source;
    struct sockaddr_in ip_address_dest;
    int sockfd, ret = 0;
    int sockopt = 1;
    struct ifreq if_ip;	/*Holds my ip address*/
    ssize_t numbytes;
    struct ifreq ifopts;    /* set promiscuous mode */
    uint8_t buffer[BUFFER_SIZE];
    char ifName[IFNAMSIZ];
     

    /*Get interface name*/
    if (argc == 2)
    {
        strcpy(ifName, argv[1]);

    }
    else{
        fprintf(stderr, "Plesae provide interface name \n");
        exit(1);
    }

    struct ether_header *eh = (struct ether_header *) buffer;
    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ether_header));
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct ether_header) + sizeof(struct iphdr));



    /* Open AF_PACKET socket, listening for EtherType */
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        perror("listener: socket"); 
        return -1;
    }

    /* Set interface to promiscuous mode *//*cpy ifname into ifr_name*/
    strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
    ioctl(sockfd, SIOCGIFFLAGS, &ifopts); 
    ifopts.ifr_flags |= IFF_PROMISC;  /*I have used bitwise OR because we should not lose other flags*/
    ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
        
    /* Bind to device */
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ-1) == -1)  {
        perror("SO_BINDTODEVICE");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFADDR, &if_ip) < 0)
    {
        perror("SIOCGIFADDR");
        exit(1);
    }

    while(1)
    {
        numbytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        
        /* Get the source's and dest's ip address*/
        ip_address_source.sin_addr.s_addr = iph->saddr;
        ip_address_dest.sin_addr.s_addr = iph->daddr;
	    
        
        inet_ntop(AF_INET, &ip_address_source.sin_addr, sender_ip, sizeof sender_ip);
        inet_ntop(AF_INET, &ip_address_dest.sin_addr, dest_ip, sizeof dest_ip);

        

        if((iph->protocol == 0x11)) //&& (strcmp(sender_ip, inet_ntoa(((struct sockaddr_in *)&if_ip.ifr_addr)->sin_addr)) == 0)) 
        {
            
            if (ntohs(udp->dest) == DEST_UDP_PORT) /*Here checks udp's inside*/
            {
                printf("Data:");
                for (int i=0; i<numbytes; i++) 
                    printf("%02x:", buffer[i]);
                printf("\n");
                send_packet("enp46s0",buffer, numbytes);
          	

                
            }
        }
        
    }

    close(sockfd);
    return ret;

}