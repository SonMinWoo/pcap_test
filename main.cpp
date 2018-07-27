#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>

#ifndef NET_STRUCT_H
#define NET_STRUCT_H

#define ETH_ALEN 6
#define ETH_HLEN 14

struct eth_hdr{
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t type;
	uint8_t data[0];
} __attribute__((packed));

#define IPV4_VER(XX) 	((uint8_t)(((XX)->VIHL & 0xF0) >> 4))
#define IPV4_HL(XX) 	((uint8_t)(((XX)->VIHL & 0x0F) << 2))

#define IPV4_HL_MIN 20
#define IPV4_ALEN 0x04

struct ipv4_header {
	uint8_t VIHL;
	uint8_t DSCP_ECN;
	uint16_t length;
	uint16_t id;
	uint16_t FF;
	uint8_t TTL;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src[4];
	uint8_t dst[4];
	uint8_t data[0];
} __attribute__((packed));

#define TCP_HL(XX) ((uint8_t)((((uint8_t*)(&(XX)->DRF))[0] & 0xF0) >> 2))
#define TCP_PAYLOAD_MAXLEN 16

struct tcp_hdr {
	uint16_t src;
	uint16_t dst;
	uint32_t seq;
	uint32_t ack;
	uint16_t DRF;
	uint16_t wsize;
	uint16_t checksum;
	uint16_t urg;
	uint8_t payload[0];
} __attribute__((packed));

#endif

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test eth0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
    const struct eth_hdr* packet_ether = (const struct eth_hdr*)packet;
    
    printf("\n----------------------------------------------\n\n");
    
    printf("Source MAC : ");

    for (int i = 0; i < ETH_ALEN; ++i) {
	printf("%s%02x", (i ? ":" : ""), packet_ether->src[i]);
    }

    printf("\nDestination MAC : ");

    for(int i = 0; i < ETH_ALEN; ++i) {
	printf("%s%02x", (i ? ":" : ""), packet_ether->dst[i]);
    }
    printf("\n");

    int eth_type = ntohs(packet_ether->type);
    if(eth_type != 0x0800){
	puts("[Ethernet type is not ipv4]\n");
	continue;
    }

    puts("Ethernet type is ipv4");

    const struct ipv4_header *pk_ipv4 = (const struct ipv4_header *)packet_ether->data;
    printf("Source IP : ");

    for (int i = 0; i < IPV4_ALEN; ++i) {
	printf("%s%d", (i ? "." : ""), pk_ipv4->src[i]);
    }

    printf("\nDestination IP : ");

    for (int i = 0; i <IPV4_ALEN; ++i){
	printf("%s%d", (i ? "." : ""), pk_ipv4->dst[i]);
    }
    printf("\n");

    uint8_t iphl = IPV4_HL(pk_ipv4);
    if(iphl < IPV4_HL_MIN){
	printf("[Invalid ipv4 packet]\n");
	return 2;
    }

    if(pk_ipv4 -> protocol != 0x06){
	printf("[This is not tcp]\n");
	continue;
    }

    puts("[[[[[ipv4 protocol is tcp]]]]]");

    const struct tcp_hdr* pk_tcp = (const struct tcp_hdr*)&pk_ipv4->data[iphl - IPV4_HL_MIN];

    uint16_t length = ntohs(pk_ipv4->length) - iphl;
    printf("Source PORT :%d\n", ntohs(pk_tcp->src));

    printf("Destination PORT : %d\n",ntohs(pk_tcp->dst));

    uint8_t thl = TCP_HL(pk_tcp);
    if(thl<20 || thl > 60){
	puts("[This is invalid tcp packet]\n");
	return 2;
    }

    uint32_t t1 = length - thl;

    printf("Data: ");

    for(uint32_t i = 0; i<16; ++i){
	printf("%s%02x", (i ? " " : ""), pk_tcp->payload[thl-20+i]);
    }
    printf("\n");


    //printf("%u bytes captured\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}
