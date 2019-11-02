// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

#include <errno.h>
#include <getopt.h>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "hashlimit.h"
#include "pmtud.h"
#include "uevent.h"

#define IFACE_RATE_PPS 10.0
#define SRC_RATE_PPS 1.1

static void usage()
{
	fprintf(stderr,
		"Usage:\n"
		"\n"
		"    pmtud [options]\n"
		"\n"
        "Path MTU Daemon listens for inbound IPv4 packets with the DF (Don't Fragment)\n"
        "bit set and sends back ICMP code 3 messages related to MTU detection\n"
		"\n"
		"Options:\n"
		"\n"
		"  --iface              Network interface to listen on\n"
		"  --src-rate           Pps limit from single source "
		"(default=%.1f pss)\n"
		"  --iface-rate         Pps limit to send on a single "
		"interface "
		"(default=%.1f pps)\n"
		"  --verbose            Print forwarded packets on screen\n"
		"  --dry-run            Don't inject packets, just dry run\n"
		"  --desired-mtu        The MTU to send back link\n"
		"  --cpu                Pin to particular cpu\n"
		"  --help               Print this message\n"
		"\n"
		"Example:\n"
		"\n"
		"    pmtud --iface=eth2 --src-rate=%.1f --iface-rate=%.1f --desired-mtu=1420\n"
		"\n",
		SRC_RATE_PPS, IFACE_RATE_PPS, SRC_RATE_PPS, IFACE_RATE_PPS);
	exit(-1);
}

#define SNAPLEN 2048
#define BPF_FILTER "ip and ip[6] == 64 and greater %d"

static int on_signal(struct uevent *uevent, int sfd, int mask, void *userdata)
{
	volatile int *done = userdata;
	int buf[512];
	/* Drain. Socket should be NONBLOCK */
	int r = read(sfd, buf, sizeof(buf));
	if (r < 0) {
		PFATAL("read()");
	}

	*done = 1;
	return 0;
}

struct state
{
	pcap_t *pcap;
	int raw_sd;
	struct hashlimit *sources;
	struct hashlimit *ifaces;
	int verbose;
	int dry_run;
	uint16_t desired_mtu;
};

static int handle_packet(const uint8_t *p, unsigned data_len, void *userdata)
{
	struct state *state = userdata;

	const char *reason = "unknown";
	int l4_sport = -1;

	/* assumming DLT_EN10MB */

	/* 14 ethernet plus the maximum MTU */
	if (data_len < 14 + state->desired_mtu) {
		reason = "Packet size within bounds";
		goto reject;
	}

	/* Check whether we're being tricked, we never known */
	/*if (p[0] == p[6] && p[1] == p[7] && p[2] == p[8] && p[3] == p[9] &&
	    p[4] == p[10] && p[5] == p[11]) {
        reason = "Invalid Ethernet header";
        goto reject;
	}*/

	const uint8_t *hash = NULL;
	int hash_len = 0;

	/* Check whether the packet has a VLAN tag */
	unsigned l3_offset = 14;
	uint16_t eth_type = (((uint16_t)p[12]) << 8) | (uint16_t)p[13];
	if (eth_type == 0x8100) {
		eth_type = (((uint16_t)p[16]) << 8) | (uint16_t)p[17];
		l3_offset = 18;
	}

	int valid = 0;
    int l3_hdr_len = 0;

	/* Handle an IPv4 packet */
	if (eth_type == 0x0800 && (p[l3_offset] & 0xF0) == 0x40) {
		l3_hdr_len = (int)(p[l3_offset] & 0x0F) * 4;
		if (l3_hdr_len < 20 || l3_hdr_len > 24) {
			reason = "IPv4 header invalid length";
			goto reject;
		}

		/* Flags : R, DF, MF. We want DF = 1 and the others = 0 */
		if ((p[l3_offset + 6] & 0xE0) == 0x40) {
            valid = 1;
            hash = &p[l3_offset + 12];
            hash_len = 4;
		}
	}

    /* Handle an IPv6 packet : do not send anything back */
	if (eth_type == 0x86dd && (p[l3_offset] & 0xF0) == 0x60) {
		reason = "IPv6 is not supported";
        goto reject;
	}

	if (valid == 0 || hash == NULL || hash_len == 0) {
		reason = "Invalid IP packet or DF not set";
		goto reject;
	}

	/* Forge our new ICMP reply packet */
	struct icmp_packet *packet = malloc(sizeof(struct icmp_packet));

	/* Set the MAC src and dst addresses */
	int i;
	for (i = 0; i < 6; i++) {
        packet->eth_dst[i] = p[6 + i];
	}

	for (i = 0; i < 6; i++) {
        packet->eth_src[i] = p[i];
	}
	packet->eth_type = 0x0008;

	uint16_t ip_chksum = 0;

	packet->ip_v_ihl = (0x04 << 4) | 0x05;
	packet->ip_tos = 0x00;
    ip_chksum += (packet->ip_v_ihl << 8) | packet->ip_tos;

	packet->ip_id = 0x0000;
	packet->ip_flags_offset = 0x0000;

	packet->ip_ttl = (u_int8_t )0x40;
	packet->ip_proto = (u_int8_t )0x01;
    ip_chksum += (packet->ip_ttl << 8) | packet->ip_proto;

	packet->ip_chksum = 0x0000;

	/* Set the IP src and dst addresses */
    for (i = 0; i < 4; i ++) {
        packet->ip_src_addr[i] = p[l3_offset + 12 + 4 + i];
    }
    ip_chksum += add_checksum(packet->ip_src_addr, 4);

	for (i = 0; i < 4; i ++) {
        packet->ip_dst_addr[i] = p[l3_offset + 12 + i];
	}
    ip_chksum += add_checksum(packet->ip_dst_addr, 4);

    uint16_t icmp_chksum = 0;

    packet->icmp_type = (u_int8_t )0x3;
    packet->icmp_code = (u_int8_t )0x4;
    icmp_chksum += ((uint16_t)packet->icmp_type << 8) | (uint16_t)packet->icmp_code;

    packet->icmp_chksum = 0x0000;
    packet->icmp_unused = 0x0000;
    packet->icmp_mtu = htons(state->desired_mtu);
    icmp_chksum += (uint16_t)state->desired_mtu;

    /* Copy the IP header + the first 8 bytes of the IP packet */
    for (i = 0; i < l3_hdr_len; i++) {
        packet->icmp_data[i] = p[l3_offset + i];
    }

    for (i = 0; i < 8; i++) {
        packet->icmp_data[i + l3_hdr_len] = p[l3_offset + l3_hdr_len + i];
    }
    icmp_chksum += add_checksum(packet->icmp_data, l3_hdr_len + 8);

    /* Set the IP packet length */
    /* ip + icmp + original_ip + 8 bytes of data */
    packet->ip_length = htons((u_int16_t)36 + (u_int16_t)l3_hdr_len);
    ip_chksum += ntohs(packet->ip_length);

    /* Compute the ICMP and IP checksums */
    packet->icmp_chksum = (icmp_chksum >> 16) + (icmp_chksum & 0xffff);
    packet->icmp_chksum += (packet->icmp_chksum >> 16);
    packet->icmp_chksum = htons(~packet->icmp_chksum - 4);

    packet->ip_chksum = (ip_chksum >> 16) + (ip_chksum & 0xffff);
    packet->ip_chksum += (packet->ip_chksum >> 16);
    packet->ip_chksum = htons(~packet->ip_chksum - 2);

	/* Check if the limits will be reached */
	int limit_src = hashlimit_check_hash(state->sources, hash, hash_len);
	int limit_iface = hashlimit_check(state->ifaces, 0);

	if (limit_src == 0) {
		reason = "Ratelimited on source IP";
		goto reject;
	}
	if (limit_iface == 0) {
		reason = "Ratelimited on outgoing interface";
		goto reject;
	}

	hashlimit_subtract_hash(state->sources, hash, hash_len);
	hashlimit_subtract(state->ifaces, 0);

	u_int8_t *pp;
	build_packet(packet, &pp, l3_hdr_len + 8, ntohs(packet->ip_length) + 14);

	reason = "transmitting";
	if (state->verbose > 2) {
		printf("%s %s mtu=%i sport=%i  data=%s\n",
		       ip_to_string(hash, hash_len), reason, state->desired_mtu,
		       l4_sport, to_hex(pp, ntohs(packet->ip_length) + 14));
	} else if (state->verbose) {
		printf("%s %s mtu=%i sport=%i\n", ip_to_string(hash, hash_len),
		       reason, state->desired_mtu, l4_sport);
	}

	if (state->dry_run == 0) {
		int r = send(state->raw_sd, pp, ntohs(packet->ip_length) + 14, 0);
        //int r = send(state->raw_sd, p, data_len, 0);
		/* ENOBUFS happens during IRQ storms okay to ignore */
		if (r < 0 && errno != ENOBUFS) {
			PFATAL("send()");
		}
	}
	return 1;

reject:
	if (state->verbose > 2) {
		printf("%s %s mtu=%i sport=%i  %s\n",
		       ip_to_string(hash, hash_len), reason, state->desired_mtu,
		       l4_sport, to_hex(p, data_len));
	} else if (state->verbose > 1) {
		printf("%s %s mtu=%i sport=%i\n", ip_to_string(hash, hash_len),
		       reason, state->desired_mtu, l4_sport);
	}

	return -1;
}

static int handle_pcap(struct uevent *uevent, int sfd, int mask, void *userdata)
{
	struct state *state = userdata;

	while (1) {
		struct pcap_pkthdr *hdr;
		const uint8_t *data;

		int r = pcap_next_ex(state->pcap, &hdr, &data);

		switch (r) {
		case 1:
			if (hdr->len == hdr->caplen) {
				handle_packet(data, hdr->caplen, state);
			} else {
				/* Partial caputre */
			}
			break;

		case 0:
			/* Timeout */
			return 0;

		case -1:
			FATAL("pcap_next_ex(): %s", pcap_geterr(state->pcap));
			break;

		case -2:
			return 0;
		}
	}
}

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"iface", required_argument, 0, 'i'},
		{"src-rate", required_argument, 0, 's'},
		{"iface-rate", required_argument, 0, 'r'},
		{"verbose", no_argument, 0, 'v'},
		{"dry-run", no_argument, 0, 'd'},
		{"cpu", required_argument, 0, 'c'},
		{"help", no_argument, 0, 'h'},
		{"desired-mtu", required_argument, 0, 'm'},
		{NULL, 0, 0, 0}};

	const char *optstring = optstring_from_long_options(long_options);
	const char *iface = NULL;

	double src_rate = SRC_RATE_PPS;
	double iface_rate = IFACE_RATE_PPS;
	int verbose = 0;
	int dry_run = 0;
	int taskset_cpu = -1;
	int desired_mtu = -1;

	optind = 1;
	while (1) {
		int option_index = 0;
		int arg = getopt_long(argc, argv, optstring, long_options,
				      &option_index);
		if (arg == -1) {
			break;
		}

		switch (arg) {
		case 0:
			FATAL("Unknown option: %s", argv[optind]);
			break;

		case 'h':
			usage();
			break;

		case '?':
			exit(-1);
			break;

		case 'i':
			iface = optarg;
			break;

		case 's':
			src_rate = atof(optarg);
			if (src_rate <= 0.0) {
				FATAL("Rates must be greater than zero");
			}
			break;

		case 'r':
			iface_rate = atof(optarg);
			if (iface_rate <= 0.0) {
				FATAL("Rates must be greater than zero");
			}
			break;
		case 'm':
			desired_mtu = atoi(optarg);
			if (desired_mtu < 0 || desired_mtu > 65535) {
				FATAL("MTU must be within range "
				      "0..65535");
			}
			break;

		case 'v':
			verbose++;
			break;

		case 'd':
			dry_run = 1;
			break;

		case 'c':
			taskset_cpu = atoi(optarg);
			break;

		default:
			FATAL("Unknown option %c: %s", arg,
			      str_quote(argv[optind]));
		}
	}

	if (argv[optind]) {
		FATAL("Not sure what you mean by %s", str_quote(argv[optind]));
	}

	if (iface == NULL) {
		FATAL("Specify interface with --iface option");
	}

	if (desired_mtu == -1) {
        FATAL("Specify desired MTU with --desired-mtu option");
	}

	if (set_core_dump(1) < 0) {
		ERRORF("[ ] Failed to enable core dumps, continuing anyway.\n");
	}

	if (taskset_cpu > -1) {
		if (taskset(taskset_cpu)) {
			ERRORF("[ ] sched_setaffinity(%i): %s\n", taskset_cpu,
			       strerror(errno));
		}
	}

	struct pcap_stat stats = {0, 0, 0};
	struct state state;
	memset(&state, 0, sizeof(struct state));
	state.sources = hashlimit_alloc(8191, src_rate, src_rate * 1.9);
	state.ifaces = hashlimit_alloc(32, iface_rate, iface_rate * 1.9);
	state.verbose = verbose;
	state.dry_run = dry_run;
	state.desired_mtu = desired_mtu;
	state.raw_sd = setup_raw(iface);

	struct uevent uevent;
	uevent_new(&uevent);


    char * filter = (char *)malloc(sizeof(BPF_FILTER) + 3* sizeof(char));

    sprintf(filter, BPF_FILTER, state.desired_mtu);
    state.pcap = setup_pcap(iface, filter, SNAPLEN, &stats);
    int pcap_fd = pcap_get_selectable_fd(state.pcap);
    if (pcap_fd < 0) {
        PFATAL("pcap_get_selectable_fd()");
    }
    uevent_yield(&uevent, pcap_fd, UEVENT_READ, handle_pcap,
             &state);


	volatile int done = 0;
	uevent_yield(&uevent, signal_desc(SIGINT), UEVENT_READ, on_signal,
		     (void *)&done);
	uevent_yield(&uevent, signal_desc(SIGTERM), UEVENT_READ, on_signal,
		     (void *)&done);

	fprintf(stderr, "[*] #%i Started pmtud ", getpid());
	fprintf(stderr, "pcap on iface=%s ", str_quote(iface));

	fprintf(stderr,
		"rates={iface=%.1f pps source=%.1f pps}, verbose=%i, "
		"dry_run=%i\n",
		iface_rate, src_rate, verbose, dry_run);

	while (done == 0) {
		struct timeval timeout =
			NSEC_TIMEVAL(MSEC_NSEC(24 * 60 * 60 * 1000UL));
		int r = uevent_select(&uevent, &timeout);
		if (r != 0) {
			continue;
		}
	}
	fprintf(stderr, "[*] #%i Quitting\n", getpid());

	unsetup_pcap(state.pcap, iface, &stats);
	fprintf(stderr, "[*] #%i recv=%i drop=%i ifdrop=%i\n", getpid(),
		stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);

	close(state.raw_sd);

	hashlimit_free(state.sources);
	hashlimit_free(state.ifaces);

	return 0;
}
