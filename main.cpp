#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test eth0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }
  int sa;
  int sb;
  int sc;
  int sd;
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
    for(int i = 0; i <68; i++){
	if(i == 0){
		printf("Destination Mac: ");
	}
	if(i == 6){
		printf("\n");
		printf("Source Mac: ");
	}
	if(i == 12){
		printf("\n");
		printf("Ethernet Type: ");
	}
	if(i == 23){
		printf("\n");
		printf("Protocol: ");
	}
	if(i == 26){
		printf("\n");
		printf("Source ip: ");
	}
	if(i == 30){
		printf("\n");
		printf("Destination ip: ");
	}
	if(i == 34){
		printf("\n");
		printf("Source port: ");
	}
	if(i == 36){
		printf("\n");
		printf("Destination port: ");
	}
	if(i == 52){
		printf("\n");
		printf("Data: ");
	}
	if(i < 14 || i == 23 || i > 51){
		printf("%02x ", *(packet+i));
	}
	if(i == 23){
		int a;
		a = (int)*(packet+i);
		if(a == 6)
			printf("(TCP)");
	}
	if(i == 34){
		sa = (int)*(packet+i);
	}
	if(i == 35){
		sb = (int)*(packet+i);
		sc = 16*16*sa;
		sd = sb+sc;
		printf("%d", sd);
	}
	if(i == 36){
		sa = (int)*(packet+i);
	}
	if(i == 37){
		sb = (int)*(packet+i);
		sc = 16*16*sa;
		sd = sb+sc;
		printf("%d",sd);
	}
	if(25 < i && i < 29){
		int c;
		c = (int)*(packet+i);
		printf("%d.", c);
	}
	if(i == 29){
		int c;
		c = (int)*(packet+i);
		printf("%d", c);
	}
	if(29 < i && i < 33){
		int c;
		c = (int)*(packet+i);
		printf("%d.", c);
	}
	if(i == 33){
		int c;
		c = (int)*(packet+i);
		printf("%d", c);
	}

	
    }
    //printf("%u bytes captured\n", header->caplen);
    printf("\n-------------------------------------------------------------\n");
  }

  pcap_close(handle);
  return 0;
}
