#include <libnet.h>
#include <libnet/libnet-types.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-headers.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#define SIZE_ETHERNET 14

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
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
    struct libnet_ethernet_hdr* ether_hdr;
    struct libnet_ipv4_hdr* ip_hdr;
    struct libnet_tcp_hdr* t_hdr;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    int no=1;
    unsigned char *pcap_data; 

    u_int size_ip;
    u_short size_tcp;
    
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);

    ether_hdr = (struct libnet_ethernet_hdr*)(packet);
    printf("source ethernet addr > ");
    for(int i=0;i<ETHER_ADDR_LEN;i++){
	    if(i!=ETHER_ADDR_LEN-1)
		    printf("%.2x:", ether_hdr->ether_shost[i]);
	    else
		    printf("%.2x\n", ether_hdr->ether_shost[i]);
    }
    printf("destination ethernet addr > ");
    for(int i=0;i<ETHER_ADDR_LEN;i++)
    {
            if(i!=ETHER_ADDR_LEN-1)
                    printf("%.2x:", ether_hdr->ether_dhost[i]);
            else
                    printf("%.2x\n", ether_hdr->ether_dhost[i]);
    }
    printf("\n");

    ip_hdr = (struct libnet_ipv4_hdr*)(packet + SIZE_ETHERNET);
    if(ip_hdr!=NULL && ntohs(ether_hdr->ether_type) == 0x0800)
    {
	size_ip =(ip_hdr->ip_hl)*4;
    	char* ip_src_str = inet_ntoa(ip_hdr->ip_src);
        printf("ip source addr > %s\n", ip_src_str);
    	char* ip_dst_str = inet_ntoa(ip_hdr->ip_dst);
    	printf("ip destination addr > %s\n", ip_dst_str);
    	if (size_ip < 20) {
		return -1;
    	}
    }
    else
    {
	printf("not ip packet\n\n");
	continue;
    }
    printf("\n");

    t_hdr = (struct libnet_tcp_hdr*)(packet + SIZE_ETHERNET + size_ip);
    printf("protocol type : %x\n", (ip_hdr->ip_p));
    if(t_hdr!=NULL && ip_hdr->ip_p == 0x06)
    {
    	size_tcp = (t_hdr->th_off)*4;
        u_int tcp_sport = ntohs(t_hdr->th_sport);
	printf("tcp source port > %d\n", tcp_sport);
	u_int tcp_dport = ntohs(t_hdr->th_dport);
        printf("tcp destination port > %d\n", tcp_dport);
    	if (size_tcp < 20) {
		return -1;
    	}
    }
    else
    {
	printf("not tcp packet\n\n");
	continue;
    }
    printf("\n");

    pcap_data = (unsigned char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    int i=0;
    if(pcap_data[i]!='\0')
    {
	printf("data > ");
	for(i=0;i<16;i++)
		printf("%02x ", pcap_data[i]);
    }
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}
