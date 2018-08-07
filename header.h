#include <stdio.h>  /* Standard I/O */
#include <stdlib.h> /* Standard Library */
#include <string.h>
#include <unistd.h>

#include <ifaddrs.h>
#include <errno.h> /* Error number and related */
#define ENUMS
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#include <features.h> /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> /* The L2 protocols */
#endif
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <pcap.h>

#define MACLEN 6

#define ARP					0x0806
#define REQUEST             0x01
#define REPLY               0x02

#define ETHERNET 			0x01
#define IPV4				0x0800
#define HWLEN				0x06
#define PTLEN				0x04

typedef struct _ethernet_header
{
	u_int8_t ether_dhost[MACLEN];
	u_int8_t ether_shost[MACLEN];
	u_int16_t ether_type;       			/* ARP : 0x0806, RARP : 0x0835 */
} ethernet_hdr;

#pragma pack(push, 1)						/* remove struct padding */
typedef struct _arp_header
{
	u_int16_t ar_hrd;
	u_int16_t ar_pro;
	u_int8_t ar_hln;
	u_int8_t ar_pln;
	u_int16_t ar_op;            			/* Request : 0x01, Reply : 0x02, RARP request : 0x03, RARP Replay : 0x04 */
	u_int8_t ar_src_mac[MACLEN];
	u_int32_t ar_src_ip;
	u_int8_t ar_dst_mac[MACLEN];
	u_int32_t ar_dst_ip;
} arp_hdr;

int get_local_mac(const char *dev, unsigned char *mac);
u_int32_t get_local_ip(const char *dev);
void ipchar_to_uint(const char *char_ip,u_int32_t *int_ip);
arp_hdr *make_arp_header(u_int16_t ar_hrd, u_int16_t ar_pro, u_int8_t ar_hln, u_int8_t ar_pln, u_int16_t ar_op, u_int8_t *ar_src_mac, u_int32_t ar_src_ip, u_int8_t *ar_dst_mac, u_int32_t ar_dst_ip);
ethernet_hdr *make_ethernet_header(u_int8_t *ether_dhost, u_int8_t *ether_shost, u_int16_t ether_type);
int receive_reply(pcap_t *handle, u_int32_t ar_src_ip, u_int8_t *ether_shost);
void print_packet(ethernet_hdr *ethernet_h, arp_hdr *arp_h);
void send_packet(pcap_t *handle, ethernet_hdr *ethernet_h, arp_hdr *arp_h, int mode);
u_int8_t* reverse_array(u_int8_t *uintarr);
void hton_ethernet(ethernet_hdr *ethernet_h);
void hton_arp(arp_hdr *arp_h);
int receive_request(pcap_t *handle, u_int32_t ar_src_ip);