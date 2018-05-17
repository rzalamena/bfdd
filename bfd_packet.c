/*********************************************************************
 * Copyright 2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * bfd_packet.c: implements the BFD protocol packet handling.
 *
 * Authors
 * -------
 * Shrijeet Mukherjee [shm@cumulusnetworks.com]
 * Kanna Rajagopal [kanna@cumulusnetworks.com]
 * Radhika Mahankali [Radhika@cumulusnetworks.com]
 */

/* XXX: fix compilation error on Ubuntu 16.04 or older. */
#ifndef _UAPI_IPV6_H
#define _UAPI_IPV6_H
#endif /* _UAPI_IPV6_H */

#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <err.h>
#include <stdint.h>
#include <unistd.h>

#include "bfd.h"

/*
 * Definitions
 */

/* iov for BFD control frames */
#define CMSG_HDR_LEN sizeof(struct cmsghdr)
#define CMSG_TTL_LEN (CMSG_HDR_LEN + sizeof(uint32_t))
#define CMSG_IN_PKT_INFO_LEN (CMSG_HDR_LEN + sizeof(struct in_pktinfo) + 4)
#define CMSG_IN6_PKT_INFO_LEN                                                  \
	(CMSG_HDR_LEN + sizeof(struct in6_addr) + sizeof(int) + 4)

typedef struct bfd_raw_echo_pkt_s {
	struct iphdr ip;
	struct udphdr udp;
	bfd_echo_pkt_t data;
} bfd_raw_echo_pkt_t;

typedef struct bfd_raw_ctrl_pkt_s {
	struct iphdr ip;
	struct udphdr udp;
	bfd_pkt_t data;
} bfd_raw_ctrl_pkt_t;

typedef struct vxlan_hdr_s {
	uint32_t flags;
	uint32_t vnid;
} vxlan_hdr_t;

#define IP_ECHO_PKT_LEN (IP_HDR_LEN + UDP_HDR_LEN + BFD_ECHO_PKT_LEN)
#define UDP_ECHO_PKT_LEN (UDP_HDR_LEN + BFD_ECHO_PKT_LEN)
#define IP_CTRL_PKT_LEN (IP_HDR_LEN + UDP_HDR_LEN + BFD_PKT_LEN)
#define UDP_CTRL_PKT_LEN (UDP_HDR_LEN + BFD_PKT_LEN)

static uint8_t msgbuf[BFD_PKT_LEN];
static struct iovec msgiov = {&(msgbuf[0]), sizeof(msgbuf)};
static uint8_t cmsgbuf[CMSG_TTL_LEN + CMSG_IN_PKT_INFO_LEN];

static struct sockaddr_in msgaddr;
static struct msghdr msghdr = {(void *)&msgaddr, sizeof(msgaddr), &msgiov, 1,
			       (void *)&cmsgbuf, sizeof(cmsgbuf), 0};

static uint8_t cmsgbuf6[CMSG_TTL_LEN + CMSG_IN6_PKT_INFO_LEN];

static struct sockaddr_in6 msgaddr6;
static struct msghdr msghdr6 = {(void *)&msgaddr6, sizeof(msgaddr6), &msgiov, 1,
				(void *)&cmsgbuf6, sizeof(cmsgbuf6), 0};

/* Berkeley Packet filter code to filter out BFD Echo packets.
 * tcpdump -dd "(udp dst port 3785)"
 */
static struct sock_filter bfd_echo_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 4, 0x000086dd},
	{0x30, 0, 0, 0x00000014}, {0x15, 0, 11, 0x00000011},
	{0x28, 0, 0, 0x00000038}, {0x15, 8, 9, 0x00000ec9},
	{0x15, 0, 8, 0x00000800}, {0x30, 0, 0, 0x00000017},
	{0x15, 0, 6, 0x00000011}, {0x28, 0, 0, 0x00000014},
	{0x45, 4, 0, 0x00001fff}, {0xb1, 0, 0, 0x0000000e},
	{0x48, 0, 0, 0x00000010}, {0x15, 0, 1, 0x00000ec9},
	{0x6, 0, 0, 0x0000ffff},  {0x6, 0, 0, 0x00000000},
};

/* Berkeley Packet filter code to filter out BFD vxlan packets.
 * tcpdump -dd "(udp dst port 4789)"
 */
static struct sock_filter bfd_vxlan_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 4, 0x000086dd},
	{0x30, 0, 0, 0x00000014}, {0x15, 0, 11, 0x00000011},
	{0x28, 0, 0, 0x00000038}, {0x15, 8, 9, 0x000012b5},
	{0x15, 0, 8, 0x00000800}, {0x30, 0, 0, 0x00000017},
	{0x15, 0, 6, 0x00000011}, {0x28, 0, 0, 0x00000014},
	{0x45, 4, 0, 0x00001fff}, {0xb1, 0, 0, 0x0000000e},
	{0x48, 0, 0, 0x00000010}, {0x15, 0, 1, 0x000012b5},
	{0x6, 0, 0, 0x0000ffff},  {0x6, 0, 0, 0x00000000},
};

static int ttlval = BFD_TTL_VAL;
static int tosval = BFD_TOS_VAL;
static int rcvttl = BFD_RCV_TTL_VAL;
static int pktinfo = BFD_PKT_INFO_VAL;

typedef struct udp_psuedo_header_s {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t reserved;
	uint8_t protocol;
	uint16_t len;
} udp_psuedo_header_t;

#define UDP_PSUEDO_HDR_LEN sizeof(udp_psuedo_header_t)

/*
 * Prototypes
 */
uint16_t checksum(uint16_t *buf, int len);
uint16_t udp4_checksum(struct iphdr *iph, uint8_t *buf, int len);
uint16_t ptm_bfd_gen_IP_ID(bfd_session *bfd);
void ptm_bfd_echo_pkt_create(bfd_session *bfd);
int ptm_bfd_echo_loopback(uint8_t *pkt, int pkt_len, struct sockaddr_ll *sll);
void ptm_bfd_vxlan_pkt_snd(bfd_session *bfd, int fbit);
int ptm_bfd_process_echo_pkt(int s);
bool ptm_bfd_validate_vxlan_pkt(bfd_session *bfd,
				bfd_session_vxlan_info_t *vxlan_info);

ssize_t bfd_recv_ipv4(int sd, bool is_mhop, char *port, size_t portlen,
		      char *vrfname, size_t vrfnamelen,
		      struct sockaddr_any *local, struct sockaddr_any *peer);
ssize_t bfd_recv_ipv6(int sd, bool is_mhop, char *port, size_t portlen,
		      char *vrfname, size_t vrfnamelen,
		      struct sockaddr_any *local, struct sockaddr_any *peer);

/* socket related prototypes */
void bp_set_ipopts(int sd);
void bp_bind_ip(int sd, uint16_t port);
void bp_set_ipv6opts(int sd);
void bp_bind_ipv6(int sd, uint16_t port);


/*
 * Functions
 */
uint16_t checksum(uint16_t *buf, int len)
{
	int nbytes = len;
	int sum = 0;
	uint16_t csum = 0;
	int size = sizeof(uint16_t);

	while (nbytes > 1) {
		sum += *buf++;
		nbytes -= size;
	}

	if (nbytes == 1) {
		*(uint8_t *)(&csum) = *(uint8_t *)buf;
		sum += csum;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	csum = ~sum;
	return (csum);
}

uint16_t udp4_checksum(struct iphdr *iph, uint8_t *buf, int len)
{
	char *ptr;
	udp_psuedo_header_t pudp_hdr;
	uint16_t csum;

	pudp_hdr.saddr = iph->saddr;
	pudp_hdr.daddr = iph->daddr;
	pudp_hdr.reserved = 0;
	pudp_hdr.protocol = iph->protocol;
	pudp_hdr.len = htons(len);

	ptr = malloc(UDP_PSUEDO_HDR_LEN + len);
	memcpy(ptr, &pudp_hdr, UDP_PSUEDO_HDR_LEN);
	memcpy(ptr + UDP_PSUEDO_HDR_LEN, buf, len);

	csum = checksum((uint16_t *)ptr, UDP_PSUEDO_HDR_LEN + len);
	free(ptr);
	return csum;
}

uint16_t ptm_bfd_gen_IP_ID(bfd_session *bfd)
{
	return (++bfd->ip_id);
}

static int _ptm_bfd_send(bfd_session *bs, bool use_layer2, uint16_t *port,
			 const void *data, size_t datalen)
{
	struct sockaddr *sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr_ll dll;
	socklen_t slen;
	ssize_t rv;
	int sd = -1;

	if (use_layer2) {
		memset(&dll, 0, sizeof(dll));
		dll.sll_family = AF_PACKET;
		dll.sll_protocol = htons(ETH_P_IP);
		memcpy(dll.sll_addr, bs->peer_mac, ETHERNET_ADDRESS_LENGTH);
		dll.sll_halen = htons(ETHERNET_ADDRESS_LENGTH);
		dll.sll_ifindex = bs->ifindex;

		sd = bglobal.bg_echo;
		sa = (struct sockaddr *)&dll;
		slen = sizeof(dll);
	} else if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6)) {
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = bs->shop.peer.sa_sin6.sin6_addr;
		sin6.sin6_port =
			(port) ? *port
			       : (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
					 ? htons(BFD_DEF_MHOP_DEST_PORT)
					 : htons(BFD_DEFDESTPORT);

		sd = bs->sock;
		sa = (struct sockaddr *)&sin6;
		slen = sizeof(sin6);
	} else {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr = bs->shop.peer.sa_sin.sin_addr;
		sin.sin_port =
			(port) ? *port
			       : (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
					 ? htons(BFD_DEF_MHOP_DEST_PORT)
					 : htons(BFD_DEFDESTPORT);

		sd = bs->sock;
		sa = (struct sockaddr *)&sin;
		slen = sizeof(sin);
	}

	rv = sendto(sd, data, datalen, 0, sa, slen);
	if (rv <= 0) {
		log_debug("%s:%d: sendto: (%d) %s\n", __FUNCTION__, __LINE__,
			  errno, strerror(errno));
		return -1;
	}
	if (rv < (ssize_t)datalen) {
		log_debug("%s:%d: sendto: sent partial data\n", __FUNCTION__,
			  __LINE__);
	}

	return 0;
}

void ptm_bfd_echo_pkt_create(bfd_session *bfd)
{
	bfd_raw_echo_pkt_t ep;
	uint8_t *pkt = bfd->echo_pkt;

	memset(&ep, 0, sizeof(bfd_raw_echo_pkt_t));
	memset(bfd->echo_pkt, 0, BFD_ECHO_PKT_TOT_LEN);

	/* Construct ethernet header information */
	memcpy(pkt, bfd->peer_mac, ETHERNET_ADDRESS_LENGTH);
	pkt = pkt + ETHERNET_ADDRESS_LENGTH;
	memcpy(pkt, bfd->local_mac, ETHERNET_ADDRESS_LENGTH);
	pkt = pkt + ETHERNET_ADDRESS_LENGTH;
	pkt[0] = ETH_P_IP / 256;
	pkt[1] = ETH_P_IP % 256;
	pkt += 2;

	/* Construct IP header information */
	ep.ip.version = 4;
	ep.ip.ihl = 5;
	ep.ip.tos = 0;
	ep.ip.tot_len = htons(IP_ECHO_PKT_LEN);
	ep.ip.id = htons(ptm_bfd_gen_IP_ID(bfd));
	ep.ip.frag_off = 0;
	ep.ip.ttl = BFD_TTL_VAL;
	ep.ip.protocol = IPPROTO_UDP;
	ep.ip.saddr = bfd->local_ip.sa_sin.sin_addr.s_addr;
	ep.ip.daddr = bfd->shop.peer.sa_sin.sin_addr.s_addr;
	ep.ip.check = checksum((uint16_t *)&ep.ip, IP_HDR_LEN);

	/* Construct UDP header information */
	ep.udp.source = htons(BFD_DEF_ECHO_PORT);
	ep.udp.dest = htons(BFD_DEF_ECHO_PORT);
	ep.udp.len = htons(UDP_ECHO_PKT_LEN);

	/* Construct Echo packet information */
	ep.data.ver = BFD_ECHO_VERSION;
	ep.data.len = BFD_ECHO_PKT_LEN;
	ep.data.my_discr = htonl(bfd->discrs.my_discr);
	ep.udp.check =
		udp4_checksum(&ep.ip, (uint8_t *)&ep.udp, UDP_ECHO_PKT_LEN);

	memcpy(pkt, &ep, sizeof(bfd_raw_echo_pkt_t));
}

void ptm_bfd_echo_snd(bfd_session *bfd)
{
	bfd_raw_echo_pkt_t *ep;
	bool use_layer2 = false;
	const void *pkt;
	size_t pktlen;
	uint16_t port = htons(BFD_DEF_ECHO_PORT);

	if (!BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
		ptm_bfd_echo_pkt_create(bfd);
		BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE);
	} else {
		/* just update the checksum and ip Id */
		ep = (bfd_raw_echo_pkt_t *)(bfd->echo_pkt + ETH_HDR_LEN);
		ep->ip.id = htons(ptm_bfd_gen_IP_ID(bfd));
		ep->ip.check = 0;
		ep->ip.check = checksum((uint16_t *)&ep->ip, IP_HDR_LEN);
	}

	if (use_layer2) {
		pkt = bfd->echo_pkt;
		pktlen = BFD_ECHO_PKT_TOT_LEN;
	} else {
		pkt = &bfd->echo_pkt[ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN];
		pktlen = BFD_ECHO_PKT_TOT_LEN
			 - (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN);
	}

	if (_ptm_bfd_send(bfd, use_layer2, &port, pkt, pktlen) != 0) {
		ERRLOG("Error sending echo pkt: %s", strerror(errno));
		return;
	}

	bfd->stats.tx_echo_pkt++;
}

int ptm_bfd_echo_loopback(uint8_t *pkt, int pkt_len, struct sockaddr_ll *sll)
{
	bfd_raw_echo_pkt_t *ep = (bfd_raw_echo_pkt_t *)(pkt + ETH_HDR_LEN);
	uint32_t temp_ip;
	uint8_t temp_mac[ETHERNET_ADDRESS_LENGTH];
	struct ethhdr *eth = (struct ethhdr *)pkt;

	/* swap the mac addresses */
	memcpy(temp_mac, eth->h_source, ETHERNET_ADDRESS_LENGTH);
	memcpy(eth->h_source, eth->h_dest, ETHERNET_ADDRESS_LENGTH);
	memcpy(eth->h_dest, temp_mac, ETHERNET_ADDRESS_LENGTH);

	/* swap ip addresses */
	temp_ip = ep->ip.saddr;
	ep->ip.saddr = ep->ip.daddr;
	ep->ip.daddr = temp_ip;

	ep->ip.ttl = ep->ip.ttl - 1;
	ep->ip.check = 0;
	ep->ip.check = checksum((uint16_t *)ep, IP_HDR_LEN);

	if (sendto(bglobal.bg_echo, pkt, pkt_len, 0, (struct sockaddr *)sll,
		   sizeof(struct sockaddr_ll))
	    < 0) {
		ERRLOG("Error sending echo pkt: %s", strerror(errno));
		return -1;
	}

	return 0;
}

void ptm_bfd_vxlan_pkt_snd(bfd_session *bfd, int fbit)
{
	bfd_raw_ctrl_pkt_t cp;
	uint8_t vxlan_pkt[BFD_VXLAN_PKT_TOT_LEN];
	uint8_t *pkt = vxlan_pkt;
	struct sockaddr_in sin;
	vxlan_hdr_t *vhdr;

	memset(pkt, 0, BFD_VXLAN_PKT_TOT_LEN);
	memset(&cp, 0, sizeof(bfd_raw_ctrl_pkt_t));

	/* Construct VxLAN header information */
	vhdr = (vxlan_hdr_t *)pkt;
	vhdr->flags = htonl(0x08000000);
	vhdr->vnid = htonl(bfd->vxlan_info.vnid << 8);
	pkt += VXLAN_HDR_LEN;

	/* Construct ethernet header information */
	memcpy(pkt, bfd->vxlan_info.peer_dst_mac, ETHERNET_ADDRESS_LENGTH);
	pkt = pkt + ETHERNET_ADDRESS_LENGTH;
	memcpy(pkt, bfd->vxlan_info.local_dst_mac, ETHERNET_ADDRESS_LENGTH);
	pkt = pkt + ETHERNET_ADDRESS_LENGTH;
	pkt[0] = ETH_P_IP / 256;
	pkt[1] = ETH_P_IP % 256;
	pkt += 2;

	/* Construct IP header information */
	cp.ip.version = 4;
	cp.ip.ihl = 5;
	cp.ip.tos = 0;
	cp.ip.tot_len = htons(IP_CTRL_PKT_LEN);
	cp.ip.id = ptm_bfd_gen_IP_ID(bfd);
	cp.ip.frag_off = 0;
	cp.ip.ttl = BFD_TTL_VAL;
	cp.ip.protocol = IPPROTO_UDP;
	cp.ip.daddr = bfd->vxlan_info.peer_dst_ip.s_addr;
	cp.ip.saddr = bfd->vxlan_info.local_dst_ip.s_addr;
	cp.ip.check = checksum((uint16_t *)&cp.ip, IP_HDR_LEN);

	/* Construct UDP header information */
	cp.udp.source = htons(BFD_DEFDESTPORT);
	cp.udp.dest = htons(BFD_DEFDESTPORT);
	cp.udp.len = htons(UDP_CTRL_PKT_LEN);

	/* Construct BFD control packet information */
	cp.data.diag = bfd->local_diag;
	BFD_SETVER(cp.data.diag, BFD_VERSION);
	BFD_SETSTATE(cp.data.flags, bfd->ses_state);
	BFD_SETDEMANDBIT(cp.data.flags, BFD_DEF_DEMAND);
	BFD_SETPBIT(cp.data.flags, bfd->polling);
	BFD_SETFBIT(cp.data.flags, fbit);
	cp.data.detect_mult = bfd->detect_mult;
	cp.data.len = BFD_PKT_LEN;
	cp.data.discrs.my_discr = htonl(bfd->discrs.my_discr);
	cp.data.discrs.remote_discr = htonl(bfd->discrs.remote_discr);
	cp.data.timers.desired_min_tx = htonl(bfd->timers.desired_min_tx);
	cp.data.timers.required_min_rx = htonl(bfd->timers.required_min_rx);
	cp.data.timers.required_min_echo = htonl(bfd->timers.required_min_echo);

	cp.udp.check =
		udp4_checksum(&cp.ip, (uint8_t *)&cp.udp, UDP_CTRL_PKT_LEN);

	memcpy(pkt, &cp, sizeof(bfd_raw_ctrl_pkt_t));
	sin.sin_family = AF_INET;
	sin.sin_addr = bfd->shop.peer.sa_sin.sin_addr;
	sin.sin_port = htons(4789);

	if (sendto(bfd->sock, vxlan_pkt, BFD_VXLAN_PKT_TOT_LEN, 0,
		   (struct sockaddr *)&sin, sizeof(struct sockaddr_in))
	    < 0) {
		ERRLOG("Error sending vxlan bfd pkt: %s", strerror(errno));
	} else {
		bfd->stats.tx_ctrl_pkt++;
	}
}

int ptm_bfd_process_echo_pkt(int s)
{
	ssize_t pkt_len;
	struct sockaddr_ll sll;
	uint32_t from_len = sizeof(struct sockaddr_ll);
	bfd_raw_echo_pkt_t *ep;
	char rx_pkt[BFD_RX_BUF_LEN];
	bfd_session *bfd;
	uint32_t my_discr = 0;

	pkt_len = recvfrom(s, rx_pkt, BFD_RX_BUF_LEN, MSG_DONTWAIT,
			   (struct sockaddr *)&sll, &from_len);
	if (pkt_len <= 0) {
		if (errno != EAGAIN)
			ERRLOG("Error receiving from BFD Echo socket: %s",
			       strerror(errno));
		return -1;
	}

	/* Check if we have at least the basic headers to send back. */
	if (pkt_len < HEADERS_MIN_LEN) {
		INFOLOG("Received short echo packet");
		return -1;
	}

	ep = (bfd_raw_echo_pkt_t *)(rx_pkt + ETH_HDR_LEN);
	/* if TTL = 255, assume that the received echo packet has
	 * to be looped back */
	if (ep->ip.ttl == BFD_TTL_VAL) {
		return ptm_bfd_echo_loopback((void *)rx_pkt, pkt_len, &sll);
	}

	/* Packet is too small for us to process */
	if (pkt_len < BFD_ECHO_PKT_TOT_LEN) {
		INFOLOG("Received short echo packet");
		return -1;
	}

	if (ep->data.my_discr == 0) {
		INFOLOG("My discriminator is zero in echo pkt from 0x%x",
			ntohl(ep->ip.saddr));
		return -1;
	}

	/* Your discriminator not zero - use it to find session */
	my_discr = ntohl(ep->data.my_discr);
	bfd = bs_session_find(my_discr);
	if (bfd == NULL) {
		INFOLOG("Failed to extract session from echo packet");
		return -1;
	}

	if (!BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
		INFOLOG("BFD echo not active - ignore echo packet");
		return -1;
	}

	bfd->stats.rx_echo_pkt++;

	/* Compute detect time */
	bfd->echo_detect_TO = bfd->remote_detect_mult * bfd->echo_xmt_TO;

	/* Update echo receive timeout. */
	bfd_echo_recvtimer_update(bfd);

	return 0;
}

void ptm_bfd_snd(bfd_session *bfd, int fbit)
{
	bfd_pkt_t cp;

	/* if the BFD session is for VxLAN tunnel, then construct and
	 * send bfd raw packet */
	if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_VXLAN)) {
		ptm_bfd_vxlan_pkt_snd(bfd, fbit);
		return;
	}

	/* Set fields according to section 6.5.7 */
	cp.diag = bfd->local_diag;
	BFD_SETVER(cp.diag, BFD_VERSION);
	cp.flags = 0;
	BFD_SETSTATE(cp.flags, bfd->ses_state);
	BFD_SETDEMANDBIT(cp.flags, BFD_DEF_DEMAND);
	BFD_SETPBIT(cp.flags, bfd->polling);
	BFD_SETFBIT(cp.flags, fbit);
	cp.detect_mult = bfd->detect_mult;
	cp.len = BFD_PKT_LEN;
	cp.discrs.my_discr = htonl(bfd->discrs.my_discr);
	cp.discrs.remote_discr = htonl(bfd->discrs.remote_discr);
	if (bfd->polling) {
		cp.timers.desired_min_tx =
			htonl(bfd->new_timers.desired_min_tx);
		cp.timers.required_min_rx =
			htonl(bfd->new_timers.required_min_rx);
	} else {
		cp.timers.desired_min_tx = htonl(bfd->timers.desired_min_tx);
		cp.timers.required_min_rx = htonl(bfd->timers.required_min_rx);
	}
	cp.timers.required_min_echo = htonl(bfd->timers.required_min_echo);

	if (_ptm_bfd_send(bfd, false, NULL, &cp, BFD_PKT_LEN) != 0) {
		ERRLOG("Error sending control pkt: %s", strerror(errno));
		return;
	}

	bfd->stats.tx_ctrl_pkt++;
}

#if 0  /* TODO VxLAN Support */
static bfd_pkt_t *
ptm_bfd_process_vxlan_pkt(int                       s,
                          ptm_sockevent_e           se,
                          void                      *udata,
                          int                       *ifindex,
                          struct sockaddr_in        *sin,
                          bfd_session_vxlan_info_t  *vxlan_info,
                          uint8_t                   *rx_pkt,
                          int                       *mlen)
{
    struct sockaddr_ll sll;
    uint32_t from_len = sizeof(struct sockaddr_ll);
    bfd_raw_ctrl_pkt_t *cp;
    uint8_t *pkt = rx_pkt;
    struct iphdr *iph;
    struct ethhdr *inner_ethh;

    *mlen = recvfrom(s, rx_pkt, BFD_RX_BUF_LEN, MSG_DONTWAIT,
                                  (struct sockaddr *)&sll, &from_len);

    if (*mlen  < 0) {
        if (errno != EAGAIN) {
            ERRLOG("Error receiving from BFD Vxlan socket %d: %m\n", s);
        }
        return NULL;
    }

    iph = (struct iphdr *)(pkt + ETH_HDR_LEN);
    pkt = pkt + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
    vxlan_info->vnid = ntohl(*((int *)(pkt + 4)));
    vxlan_info->vnid = vxlan_info->vnid >> 8;

    pkt = pkt + VXLAN_HDR_LEN;
    inner_ethh = (struct ethhdr *)pkt;

    cp = (bfd_raw_ctrl_pkt_t *)(pkt + ETH_HDR_LEN);

    /* Discard the non BFD packets */
    if (ntohs(cp->udp.dest) != BFD_DEFDESTPORT)
        return NULL;

    *ifindex = sll.sll_ifindex;
    sin->sin_addr.s_addr = iph->saddr;
    sin->sin_port = ntohs(cp->udp.dest);

    vxlan_info->local_dst_ip.s_addr = cp->ip.daddr;
    memcpy(vxlan_info->local_dst_mac, inner_ethh->h_dest,
			ETHERNET_ADDRESS_LENGTH);

    return (&cp->data);
}
#endif /* VxLAN */

bool ptm_bfd_validate_vxlan_pkt(bfd_session *bfd,
				bfd_session_vxlan_info_t *vxlan_info)
{
	if (bfd->vxlan_info.check_tnl_key && (vxlan_info->vnid != 0)) {
		ERRLOG("Error Rx BFD Vxlan pkt with non-zero vnid %d",
		       vxlan_info->vnid);
		return false;
	}

	if (bfd->vxlan_info.local_dst_ip.s_addr
	    != vxlan_info->local_dst_ip.s_addr) {
		ERRLOG("Error Rx BFD Vxlan pkt with wrong inner dst IP %s",
		       inet_ntoa(vxlan_info->local_dst_ip));
		return false;
	}

	if (memcmp(bfd->vxlan_info.local_dst_mac, vxlan_info->local_dst_mac,
		   ETHERNET_ADDRESS_LENGTH)) {
		ERRLOG("Error Rx BFD Vxlan pkt with wrong inner dst"
		       " MAC %02x:%02x:%02x:%02x:%02x:%02x",
		       vxlan_info->local_dst_mac[0],
		       vxlan_info->local_dst_mac[1],
		       vxlan_info->local_dst_mac[2],
		       vxlan_info->local_dst_mac[3],
		       vxlan_info->local_dst_mac[4],
		       vxlan_info->local_dst_mac[5]);
		return false;
	}

	return true;
}

ssize_t bfd_recv_ipv4(int sd, bool is_mhop, char *port, size_t portlen,
		      char *vrfname, size_t vrfnamelen,
		      struct sockaddr_any *local, struct sockaddr_any *peer)
{
	struct cmsghdr *cm;
	struct in_pktinfo *pi = NULL;
	ssize_t mlen;
	uint32_t ttl;

	memset(port, 0, portlen);
	memset(vrfname, 0, vrfnamelen);
	memset(local, 0, sizeof(*local));
	memset(peer, 0, sizeof(*peer));

	if ((mlen = recvmsg(sd, &msghdr, MSG_DONTWAIT)) == -1) {
		if (errno != EAGAIN) {
			ERRLOG("Error receiving from BFD socket: %s",
			       strerror(errno));
		}
		return -1;
	}

	/* Get source address */
	peer->sa_sin = *((struct sockaddr_in *)(msghdr.msg_name));

	/* Get and check TTL */
	for (cm = CMSG_FIRSTHDR(&msghdr); cm != NULL;
	     cm = CMSG_NXTHDR(&msghdr, cm)) {
		if (cm->cmsg_level != SOL_IP)
			continue;

		if (cm->cmsg_type == IP_TTL) {
			memcpy(&ttl, CMSG_DATA(cm), sizeof(ttl));
			if ((is_mhop == false) && (ttl != BFD_TTL_VAL)) {
				INFOLOG("Received pkt with invalid TTL %u from %s flags: %d",
					ttl, satostr(peer), msghdr.msg_flags);
				return -1;
			}
		} else if (cm->cmsg_type == IP_PKTINFO) {
			pi = (struct in_pktinfo *)CMSG_DATA(cm);
			if (pi) {
				local->sa_sin.sin_family = AF_INET;
				local->sa_sin.sin_addr = pi->ipi_addr;
				fetch_portname_from_ifindex(pi->ipi_ifindex,
							    port, portlen);
			}
		}
	}

	return mlen;
}

ssize_t bfd_recv_ipv6(int sd, bool is_mhop, char *port, size_t portlen,
		      char *vrfname, size_t vrfnamelen,
		      struct sockaddr_any *local, struct sockaddr_any *peer)
{
	struct cmsghdr *cm;
	struct in6_pktinfo *pi6 = NULL;
	ssize_t mlen;

	memset(port, 0, portlen);
	memset(vrfname, 0, vrfnamelen);
	memset(local, 0, sizeof(*local));
	memset(peer, 0, sizeof(*peer));

	if ((mlen = recvmsg(sd, &msghdr6, MSG_DONTWAIT)) == -1) {
		if (errno != EAGAIN) {
			ERRLOG("Error receiving from BFD socket: %s",
			       strerror(errno));
		}
		return -1;
	}

	/* Get source address */
	peer->sa_sin6 = *((struct sockaddr_in6 *)(msghdr6.msg_name));

	/* Get and check TTL */
	for (cm = CMSG_FIRSTHDR(&msghdr6); cm != NULL;
	     cm = CMSG_NXTHDR(&msghdr6, cm)) {
		if (cm->cmsg_level != IPPROTO_IPV6)
			continue;

		if (cm->cmsg_type == IPV6_2292HOPLIMIT) {
			memcpy(&ttlval, CMSG_DATA(cm), 4);
			if ((is_mhop == false) && (ttlval != BFD_TTL_VAL)) {
				INFOLOG("Received pkt with invalid TTL %u from %s flags: %d\n",
					ttlval, satostr(peer),
					msghdr.msg_flags);
				return -1;
			}
		} else if (cm->cmsg_type == IPV6_2292PKTINFO) {
			pi6 = (struct in6_pktinfo *)CMSG_DATA(cm);
			if (pi6) {
				local->sa_sin.sin_family = AF_INET6;
				local->sa_sin6.sin6_addr = pi6->ipi6_addr;
				fetch_portname_from_ifindex(pi6->ipi6_ifindex,
							    port, portlen);
			}
		}
	}

	return mlen;
}

void bfd_recv_cb(evutil_socket_t sd, short events __attribute__((unused)),
		 void *arg __attribute__((unused)))
{
	bfd_session *bfd;
	bfd_pkt_t *cp;
	bool is_mhop, is_vxlan;
	ssize_t mlen = 0;
	uint8_t old_state;
	uint32_t oldEchoXmt_TO, oldXmtTime;
	struct sockaddr_any local, peer;
	char port[MAXNAMELEN + 1], vrfname[MAXNAMELEN + 1];
	bfd_session_vxlan_info_t vxlan_info;

	if (sd == bglobal.bg_echo) {
		ptm_bfd_process_echo_pkt(sd);
		return;
	}

	is_mhop = is_vxlan = false;
	if (sd == bglobal.bg_shop || sd == bglobal.bg_mhop) {
		is_mhop = sd == bglobal.bg_mhop;
		mlen = bfd_recv_ipv4(sd, is_mhop, port, sizeof(port), vrfname,
				     sizeof(vrfname), &local, &peer);
	} else if (sd == bglobal.bg_shop6 || sd == bglobal.bg_mhop6) {
		is_mhop = sd == bglobal.bg_mhop6;
		mlen = bfd_recv_ipv6(sd, is_mhop, port, sizeof(port), vrfname,
				     sizeof(vrfname), &local, &peer);
	}
#if 0 /* TODO vxlan handling */
cp = ptm_bfd_process_vxlan_pkt(s, se, udata, &local_ifindex,
																&sin, &vxlan_info, rx_pkt, &mlen);
if (!cp) {
		return -1;
}
is_vxlan = true;
/* keep in network-byte order */
peer.ip4_addr.s_addr = sin.sin_addr.s_addr;
peer.family = AF_INET;
strcpy(peer_addr, inet_ntoa(sin.sin_addr));
#endif

	/* Implement RFC 5880 6.8.6 */
	if (mlen < BFD_PKT_LEN) {
		INFOLOG("Received short packet from %s", satostr(&peer));
		return;
	}

	cp = (bfd_pkt_t *)(msghdr.msg_iov->iov_base);
	if (BFD_GETVER(cp->diag) != BFD_VERSION) {
		INFOLOG("Received bad version %d from %s", BFD_GETVER(cp->diag),
			satostr(&peer));
		return;
	}

	if (cp->detect_mult == 0) {
		INFOLOG("Detect Mult is zero in pkt from %s", satostr(&peer));
		return;
	}

	if ((cp->len < BFD_PKT_LEN) || (cp->len > mlen)) {
		INFOLOG("Invalid length %d in control pkt from %s", cp->len,
			satostr(&peer));
		return;
	}

	if (cp->discrs.my_discr == 0) {
		INFOLOG("My discriminator is zero in pkt from %s",
			satostr(&peer));
		return;
	}

	if ((bfd = ptm_bfd_sess_find(cp, port, &peer, &local, vrfname, is_mhop))
	    == NULL) {
		DLOG("Failed to generate session from remote packet");
		return;
	}

	if (is_vxlan && !ptm_bfd_validate_vxlan_pkt(bfd, &vxlan_info)) {
		return;
	}

	bfd->stats.rx_ctrl_pkt++;
	if (is_mhop) {
		if ((BFD_TTL_VAL - bfd->mh_ttl) > ttlval) {
			DLOG("Exceeded max hop count of %d, dropped pkt from"
			     " %s with TTL %d",
			     bfd->mh_ttl, satostr(&peer), ttlval);
			return;
		}
	} else if (bfd->local_ip.sa_sin.sin_family == AF_UNSPEC) {
		bfd->local_ip = local;
	}

	if ((bfd->discrs.remote_discr != 0)
	    && (bfd->discrs.remote_discr != ntohl(cp->discrs.my_discr))) {
		DLOG("My Discriminator mismatch in pkt"
		     "from %s, Expected %d Got %d",
		     satostr(&peer), bfd->discrs.remote_discr,
		     ntohl(cp->discrs.my_discr));
	}

	bfd->discrs.remote_discr = ntohl(cp->discrs.my_discr);

	/* If received the Final bit, the new values should take effect */
	if (bfd->polling && BFD_GETFBIT(cp->flags)) {
		bfd->timers.desired_min_tx = bfd->new_timers.desired_min_tx;
		bfd->timers.required_min_rx = bfd->new_timers.required_min_rx;
		bfd->new_timers.desired_min_tx = 0;
		bfd->new_timers.required_min_rx = 0;
		bfd->polling = 0;
	}

	if (!bfd->demand_mode) {
		/* Compute detect time */
		bfd->detect_TO = cp->detect_mult
				 * ((bfd->timers.required_min_rx
				     > ntohl(cp->timers.desired_min_tx))
					    ? bfd->timers.required_min_rx
					    : ntohl(cp->timers.desired_min_tx));
		bfd->remote_detect_mult = cp->detect_mult;
	} else {
		ERRLOG("Unsupport BFD mode detected");
	}

	/* Save remote diagnostics before state switch. */
	bfd->remote_diag = cp->diag & BFD_DIAGMASK;

	/* State switch from section 6.8.6 */
	old_state = bfd->ses_state;
	if (BFD_GETSTATE(cp->flags) == PTM_BFD_ADM_DOWN) {
		if (bfd->ses_state != PTM_BFD_DOWN) {
			ptm_bfd_ses_dn(bfd, BFD_DIAGNEIGHDOWN);
		}
	} else {
		switch (bfd->ses_state) {
		case (PTM_BFD_DOWN):
			if (BFD_GETSTATE(cp->flags) == PTM_BFD_INIT) {
				ptm_bfd_ses_up(bfd);
			} else if (BFD_GETSTATE(cp->flags) == PTM_BFD_DOWN) {
				bfd->ses_state = PTM_BFD_INIT;
			} /* UP stays in DOWN state */
			break;
		case (PTM_BFD_INIT):
			if (BFD_GETSTATE(cp->flags) == PTM_BFD_INIT
			    || BFD_GETSTATE(cp->flags) == PTM_BFD_UP) {
				ptm_bfd_ses_up(bfd);
			} /* DOWN stays in INIT state */
			break;
		case (PTM_BFD_UP):
			if (BFD_GETSTATE(cp->flags) == PTM_BFD_DOWN) {
				ptm_bfd_ses_dn(bfd, BFD_DIAGNEIGHDOWN);
			} /* INIT and UP stays in UP state */
			break;
		}
	}

	if (old_state != bfd->ses_state) {
		DLOG("BFD Sess %d [%s] Old State [%s] : New State [%s]",
		     bfd->discrs.my_discr, satostr(&peer),
		     state_list[old_state].str, state_list[bfd->ses_state].str);
	}

	if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO)) {
		if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
			if (!ntohl(cp->timers.required_min_echo)) {
				ptm_bfd_echo_stop(bfd, 1);
			} else {
				oldEchoXmt_TO = bfd->echo_xmt_TO;
				bfd->echo_xmt_TO =
					bfd->timers.required_min_echo;
				if (ntohl(cp->timers.required_min_echo)
				    > bfd->echo_xmt_TO)
					bfd->echo_xmt_TO = ntohl(
						cp->timers.required_min_echo);
				if (oldEchoXmt_TO != bfd->echo_xmt_TO)
					ptm_bfd_echo_start(bfd);
			}
		} else if (ntohl(cp->timers.required_min_echo)) {
			bfd->echo_xmt_TO = bfd->timers.required_min_echo;
			if (ntohl(cp->timers.required_min_echo)
			    > bfd->echo_xmt_TO)
				bfd->echo_xmt_TO =
					ntohl(cp->timers.required_min_echo);
			ptm_bfd_echo_start(bfd);
		}
	}

	if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {

		if (!ntohl(cp->timers.required_min_echo)) {
		}
		bfd->echo_xmt_TO = bfd->timers.required_min_echo;
		if (ntohl(cp->timers.required_min_echo) > bfd->echo_xmt_TO)
			bfd->echo_xmt_TO = ntohl(cp->timers.required_min_echo);
	}

	/* Calculate new transmit time */
	oldXmtTime = bfd->xmt_TO;
	bfd->xmt_TO =
		(bfd->timers.desired_min_tx > ntohl(cp->timers.required_min_rx))
			? bfd->timers.desired_min_tx
			: ntohl(cp->timers.required_min_rx);

	/* If transmit time has changed, and too much time until next xmt,
	 * restart
	 */
	if (BFD_GETPBIT(cp->flags)) {
		ptm_bfd_xmt_TO(bfd, 1);
	} else if (oldXmtTime != bfd->xmt_TO) {
		/* XXX add some skid to this as well */
		ptm_bfd_start_xmt_timer(bfd, false);
	}

	if (!bfd->demand_mode) {
		/* Restart detection timer (packet received) */
		bfd_recvtimer_update(bfd);
	} else {
		ERRLOG("Unsupport BFD mode detected");
	}

	/*
	 * Save the timers and state sent by the remote end
	 * for debugging and statistics.
	 */
	if (BFD_GETFBIT(cp->flags)) {
		bfd->remote_timers.desired_min_tx =
			ntohl(cp->timers.desired_min_tx);
		bfd->remote_timers.required_min_rx =
			ntohl(cp->timers.required_min_rx);
		bfd->remote_timers.required_min_echo =
			ntohl(cp->timers.required_min_echo);

		control_notify_config(BCM_NOTIFY_CONFIG_UPDATE, bfd);
	}
}


/*
 * Sockets creation.
 */


/*
 * IPv4 sockets
 */
int bp_set_ttl(int sd)
{
	if (setsockopt(sd, SOL_IP, IP_TTL, &ttlval, sizeof(ttlval)) == -1) {
		log_warning("%s: setsockopt(IP_TTL): %s\n", __FUNCTION__,
			    strerror(errno));
		return -1;
	}

	return 0;
}

int bp_set_tos(int sd)
{
	if (setsockopt(sd, IPPROTO_IP, IP_TOS, &tosval, sizeof(tosval)) == -1) {
		log_warning("%s: setsockopt(IP_TOS): %s\n", __FUNCTION__,
			    strerror(errno));
		return -1;
	}

	return 0;
}

void bp_set_ipopts(int sd)
{
	if (bp_set_ttl(sd) != 0)
		log_fatal("%s: TTL configuration failed\n", __FUNCTION__);

	if (setsockopt(sd, SOL_IP, IP_RECVTTL, &rcvttl, sizeof(rcvttl)) == -1)
		log_fatal("%s: setsockopt(IP_RECVTTL): %s\n", __FUNCTION__,
			  strerror(errno));

	if (setsockopt(sd, SOL_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo)) == -1)
		log_fatal("%s: setsockopt(IP_PKTINFO): %s\n", __FUNCTION__,
			  strerror(errno));
}

void bp_bind_ip(int sd, uint16_t port)
{
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		log_fatal("%s: bind: %s\n", __FUNCTION__, strerror(errno));
}

int bp_udp_shop(void)
{
	int sd;

	sd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (sd == -1)
		log_fatal("%s: socket: %s\n", __FUNCTION__, strerror(errno));

	bp_set_ipopts(sd);
	bp_bind_ip(sd, BFD_DEFDESTPORT);

	return sd;
}

int bp_udp_mhop(void)
{
	int sd;

	sd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (sd == -1)
		log_fatal("%s: socket: %s\n", __FUNCTION__, strerror(errno));

	bp_set_ipopts(sd);
	bp_bind_ip(sd, BFD_DEF_MHOP_DEST_PORT);

	return sd;
}

int bp_peer_socket(struct bfd_peer_cfg *bpc)
{
	int sd, pcount;
	struct sockaddr_in sin;
	static int srcPort = BFD_SRCPORTINIT;

	sd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (sd == -1)
		return -1;

	if (!bpc->bpc_has_vxlan) {
		/* Set TTL to 255 for all transmitted packets */
		if (bp_set_ttl(sd) != 0) {
			close(sd);
			return -1;
		}
	}

	/* Set TOS to CS6 for all transmitted packets */
	if (bp_set_tos(sd) != 0) {
		close(sd);
		return -1;
	}

	/* dont bind-to-device incase of vxlan */
	if (!bpc->bpc_has_vxlan && bpc->bpc_has_localif) {
		if (bp_bind_dev(sd, bpc->bpc_localif) != 0) {
			close(sd);
			return -1;
		}
	} else if (bpc->bpc_mhop && bpc->bpc_has_vrfname) {
		if (bp_bind_dev(sd, bpc->bpc_vrfname) != 0) {
			close(sd);
			return -1;
		}
	}

	/* Find an available source port in the proper range */
	sin = bpc->bpc_local.sa_sin;
	if (bpc->bpc_mhop || bpc->bpc_has_vxlan) {
		sin.sin_addr = bpc->bpc_local.sa_sin.sin_addr;
	} else {
		sin.sin_addr.s_addr = INADDR_ANY;
	}

	pcount = 0;
	do {
		if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
			/* Searched all ports, none available */
			ERRLOG("Can't find source port for new session: %s",
			       strerror(errno));
			close(sd);
			return -1;
		}
		if (srcPort >= BFD_SRCPORTMAX)
			srcPort = BFD_SRCPORTINIT;
		sin.sin_port = htons(srcPort++);
	} while (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0);

	return sd;
}


/*
 * IPv6 sockets
 */

int bp_peer_socketv6(struct bfd_peer_cfg *bpc)
{
	int sd, pcount, ifindex;
	struct sockaddr_in6 sin6;
	static int srcPort = BFD_SRCPORTINIT;

	if ((sd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP))
	    == -1)
		return -1;

	if (!bpc->bpc_has_vxlan) {
		/* Set TTL to 255 for all transmitted packets */
		if (bp_set_ttlv6(sd) != 0) {
			close(sd);
			return -1;
		}
	}

	/* Set TOS to CS6 for all transmitted packets */
	if (bp_set_tosv6(sd) != 0) {
		close(sd);
		return -1;
	}

	/* Find an available source port in the proper range */
	memset(&sin6, 0, sizeof(struct sockaddr_in6));
	sin6 = bpc->bpc_local.sa_sin6;
	if (sin6.sin6_family != AF_INET6) {
#if 0 /* XXX what is this? */
		ifindex = ptm_bfd_fetch_ifindex(bpc->bpc_localif);
		if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr))
			sin6.sin6_scope_id = ifindex;
#endif
	} else if (bpc->bpc_has_localif) {
		ifindex = ptm_bfd_fetch_ifindex(bpc->bpc_localif);
		sin6.sin6_scope_id = ifindex;
	}

	if (bpc->bpc_has_localif) {
		if (bp_bind_dev(sd, bpc->bpc_localif) != 0) {
			close(sd);
			return -1;
		}
	} else if (bpc->bpc_mhop && bpc->bpc_has_vrfname) {
		if (bp_bind_dev(sd, bpc->bpc_vrfname) != 0) {
			close(sd);
			return -1;
		}
	}

	pcount = 0;
	do {
		if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
			/* Searched all ports, none available */
			ERRLOG("Can't find source port for new session: %s",
			       strerror(errno));
			close(sd);
			return -1;
		}
		if (srcPort >= BFD_SRCPORTMAX)
			srcPort = BFD_SRCPORTINIT;
		sin6.sin6_port = htons(srcPort++);
	} while (bind(sd, (struct sockaddr *)&sin6, sizeof(sin6)) < 0);

	return sd;
}

int bp_set_ttlv6(int sd)
{
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttlval,
		       sizeof(ttlval))
	    == -1) {
		log_warning("%s: setsockopt(IP_TTL): %s\n", __FUNCTION__,
			    strerror(errno));
		return -1;
	}

	return 0;
}

int bp_set_tosv6(int sd)
{
	if (setsockopt(sd, IPPROTO_IPV6, IPV6_TCLASS, &tosval, sizeof(tosval))
	    == -1) {
		log_warning("%s: setsockopt(IP_TOS): %s\n", __FUNCTION__,
			    strerror(errno));
		return -1;
	}

	return 0;
}

void bp_set_ipv6opts(int sd)
{
	static int ipv6_pktinfo = BFD_IPV6_PKT_INFO_VAL;
	static int ipv6_only = BFD_IPV6_ONLY_VAL;

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttlval,
		       sizeof(ttlval))
	    == -1)
		log_fatal("%s: setsockopt(IPV6_UNICAST_HOPS): %s\n",
			  __FUNCTION__, strerror(errno));

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_2292HOPLIMIT, &rcvttl,
		       sizeof(rcvttl))
	    == -1)
		log_fatal("%s: setsockopt(IPV6_2292HOPLIMIT): %s\n",
			  __FUNCTION__, strerror(errno));

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_2292PKTINFO, &ipv6_pktinfo,
		       sizeof(ipv6_pktinfo))
	    == -1)
		log_fatal("%s: setsockopt(IPV6_2292PKTINFO): %s\n",
			  __FUNCTION__, strerror(errno));

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only,
		       sizeof(ipv6_only))
	    == -1)
		log_fatal("%s: setsockopt(IPV6_V6ONLY): %s\n", __FUNCTION__,
			  strerror(errno));
}

void bp_bind_ipv6(int sd, uint16_t port)
{
	struct sockaddr_in6 sin6;

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = in6addr_any;
	sin6.sin6_port = htons(port);
	if (bind(sd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1)
		log_fatal("%s: bind: %s\n", __FUNCTION__, strerror(errno));
}

int bp_udp6_shop(void)
{
	int sd;

	sd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (sd == -1)
		log_fatal("%s: socket: %s\n", __FUNCTION__, strerror(errno));

	bp_set_ipv6opts(sd);
	bp_bind_ipv6(sd, BFD_DEFDESTPORT);

	return sd;
}

int bp_udp6_mhop(void)
{
	int sd;

	sd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (sd == -1)
		log_fatal("%s: socket: %s\n", __FUNCTION__, strerror(errno));

	bp_set_ipv6opts(sd);
	bp_bind_ipv6(sd, BFD_DEF_MHOP_DEST_PORT);

	return sd;
}


/*
 * Special sockets
 */

int bp_bind_dev(int sd, const char *dev)
{
	size_t devlen = strlen(dev) + 1;

	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, dev, devlen) == -1) {
		log_warning("%s: setsockopt(SO_BINDTODEVICE, \"%s\"): %s\n",
			    __FUNCTION__, dev, strerror(errno));
		return -1;
	}

	return 0;
}

int ptm_bfd_echo_sock_init(void)
{
	int s;
	struct sock_fprog bpf = {.len = sizeof(bfd_echo_filter)
					/ sizeof(bfd_echo_filter[0]),
				 .filter = bfd_echo_filter};

	if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
		ERRLOG("%s: socket: %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))
	    == -1) {
		ERRLOG("%s: setsockopt(SO_ATTACH_FILTER): %s\n", __FUNCTION__,
		       strerror(errno));
		close(s);
		return -1;
	}

	return s;
}

int ptm_bfd_vxlan_sock_init(void)
{
	int s;
	struct sock_fprog bpf = {.len = sizeof(bfd_vxlan_filter)
					/ sizeof(bfd_vxlan_filter[0]),
				 .filter = bfd_vxlan_filter};

	if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1) {
		ERRLOG("%s: socket: %s\n", __FUNCTION__, strerror(errno));
		return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))
	    == -1) {
		ERRLOG("%s: setsockopt(SO_ATTACH_FILTER): %s\n", __FUNCTION__,
		       strerror(errno));
		close(s);
		return -1;
	}

	return s;
}
