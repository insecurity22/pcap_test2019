#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

using namespace std;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* packet) {

    printf("%02X:%02X:%02X:%02X:%02X:%02X\n",
           packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
}

void print_ip(u_int32_t ipaddr) {

    struct in_addr ip_addr;
    ip_addr.s_addr = ipaddr;
    printf("%s\n", inet_ntoa(ip_addr));
}

int main(int argc, char *argv[])
{
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

    int res;
    struct pcap_pkthdr* header;
    const u_char* packet;

    struct ether_header *eth_h;
    struct iphdr *ip_h;
    struct tcphdr *tcp_h;

    while(res = pcap_next_ex(handle, &header, &packet)) { // get captured packet data

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        printf("***** Pcap test *****");
        eth_h = (ether_header *)packet;
        printf("\n\nSource mac : ");
        print_mac(eth_h->ether_shost);
        printf("\nDestination mac : ");
        print_mac(eth_h->ether_dhost);

        if(eth_h->ether_type == ntohs(0x0800)) {

            ip_h = (iphdr *)(packet + sizeof(ether_header)); // 14byte
            printf("\nSource IP : ");
            print_ip(ip_h->saddr);
            printf("\nDestination IP : ");
            print_ip(ip_h->daddr);

            if(ip_h->protocol == 0x06) {
                tcp_h = (tcphdr *)(packet + sizeof(ether_header) + (ip_h->ihl * 4));
                printf("\nSource port: %d", ntohs(tcp_h->source));
                printf("\nDestination port: %d", ntohs(tcp_h->dest));

                packet += sizeof(ether_header) + (ip_h->ihl*4) + sizeof(tcphdr);
                printf("\n\nData : ");
                for(int i=0; i<=10; i++) {
                    printf("%02x ", packet[i]);
                }
            }
        } else if(eth_h->ether_type == ntohs(0x0806)) {
            printf("ARP");
        }
        printf("\n\n\n\n\n");
    }

    pcap_close(handle);
    return 0;
}
