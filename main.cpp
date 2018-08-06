#include "header.h"

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		printf("wrong!\n[format] sudo ./send_arp <devname> <victim ip> <gateway ip>\n");
		return -1;
	}
	char *dev = argv[1];
	const char *vic_ip_char = (const char *)argv[2];
	const char *gate_ip_char = (const char *)argv[3];

	u_int8_t *local_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);
	get_local_mac(dev, local_mac);

	u_int8_t *null_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);
	*null_mac = 0xFFFFFFFFFFFF;

	u_int32_t vic_ip;
	ipchar_to_uint(vic_ip_char, &vic_ip);

	u_int32_t gate_ip;
	ipchar_to_uint(gate_ip_char, &gate_ip);

	/* make arp request packet */
	ethernet_hdr *ethernet_h = make_ethernet_header(
		local_mac,
		null_mac,
		REQUEST);
	arp_hdr *arp_h = make_arp_header(
		0x01,
		0x0800,
		0x06,
		0x08,
		REQUEST,
		local_mac,
		0xffffffff,
		null_mac,
		vic_ip);

	print_packet(ethernet_h, arp_h);
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

u_int32_t get_local_ip(const char *dev){


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
	arp_h->ar_src_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);
	arp_h->ar_dst_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);

	arp_h->ar_hrd = ar_hrd;
	arp_h->ar_pro = ar_pro;
	arp_h->ar_hln = ar_hln;
	arp_h->ar_pln = ar_pln;
	arp_h->ar_op = ar_op;
	arp_h->ar_src_mac = ar_src_mac;
	arp_h->ar_src_ip = ar_src_ip;
	arp_h->ar_dst_mac = ar_dst_mac;
	arp_h->ar_dst_ip = ar_dst_ip;
	return arp_h;
}

ethernet_hdr *make_ethernet_header(u_int8_t *ether_dhost, u_int8_t *ether_shost, u_int16_t ether_type)
{
	ethernet_hdr *ethernet_h = (ethernet_hdr *)(malloc(sizeof(ethernet_h)));
	ethernet_h->ether_dhost = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);
	ethernet_h->ether_shost = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);

	ethernet_h->ether_dhost = ether_dhost;
	ethernet_h->ether_shost = ether_shost;
	ethernet_h->ether_type = ether_type;
	return ethernet_h;
}

const u_char *receive_reply(char *dev, u_int8_t *ar_src_ip)
{

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	const u_char *packet;

	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s : %s\n", dev, errbuf);
		return NULL;
	}

	while (true)
	{
		struct pcap_pkthdr *header;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0)
			continue;
		if (res == -1 || res == -2)
			break;
		printf("%u bytes captured\n", header->caplen);

		ethernet_hdr *ethernet_h = (ethernet_hdr *)malloc(sizeof(ethernet_hdr));
		ethernet_h = (ethernet_hdr *)packet;

		if (ntohs(ethernet_h->ether_type) == ARP)
		{
			arp_hdr *arp_h = (arp_hdr *)malloc(sizeof(arp_hdr));
			if (ntohs(arp_h->ar_op) == REPLY)
			{
				printf("yaho!");
				print_packet((ethernet_hdr *)packet, (arp_hdr *)(packet + 14));
				/* compare ip address */
				break;
			}
		}
	}
	return packet;
}

void print_packet(ethernet_hdr *ethernet_h, arp_hdr *arp_h)
{

	/* print ethernet header */
	printf("[ETHERNET HEADER]\n");
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
	printf("Destination MAC : ");
	for (int i = 0; i < MACLEN; i++)
	{
		printf("%02x ", *(arp_h->ar_dst_mac + i));
	}
	printf("\nDestination IP : ");
	printf("%0x", arp_h->ar_dst_ip);

	printf("\nSource MAC : ");
	for (int i = 0; i < MACLEN; i++)
	{
		printf("%02x ", *(arp_h->ar_src_mac + i));
	}

	printf("\nSource IP : ");
	printf("%0x", arp_h->ar_src_ip);

	printf("\nARP OP : ");
	printf("%04x", arp_h->ar_op);
}

void send_packet(char *dev, ethernet_hdr *ethernet_h, arp_hdr *arp_h, int mode)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char *packet;
	int packet_size;

	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s : %s\n", dev, errbuf);
	}

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
	packet = (u_char *)malloc(packet_size);
	*packet = *(u_char *)ethernet_h;
	*(packet + 14) = *(u_char *)arp_h;

	if (pcap_sendpacket(handle, packet, packet_size) != 0)
	{
		fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(handle));
	}
}

/*
void send_reply(char *dev, const char *victim, const char *gateway)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[32];

	if ((fp = pcap_open_live(dev, BUFSIZ, 0, 0, errbuf)) == NULL)
	{
		fprintf(stderr, "tt");
		return;
	}
	// make arp packet! 
	arp_hdr *arp_h = (arp_hdr *)malloc(sizeof(arp_hdr));
	arp_h->ar_src_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);
	arp_h->ar_dst_mac = (u_int8_t *)malloc(sizeof(u_int8_t) * MACLEN);

	arp_h->ar_hrd = 0x0001;
	arp_h->ar_pro = 0x0800;
	arp_h->ar_hln = 0x06;
	arp_h->ar_pln = 0x04;
	arp_h->ar_op = 0x0002;

	get_local_mac(dev, arp_h->ar_src_mac);

	for (int i = 0; i < MACLEN; i++)
	{
		printf("%02x ", arp_h->ar_src_mac[i]);
	}

	for (int i = 0; i < MACLEN; i++)
	{
		arp_h->ar_dst_mac[i] = 0xff;
	}


	ipchar_to_uint(gateway, &arp_h->ar_src_ip);
	printf("src_ip : %x\n", arp_h->ar_src_ip);

	ipchar_to_uint(victim, &arp_h->ar_dst_ip);
	printf("dst_ip : %x\n", arp_h->ar_dst_ip);

}
*/