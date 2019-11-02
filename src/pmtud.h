// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

#define ERRORF(x...) fprintf(stderr, x)

#define FATAL(x...)                                                            \
	do {                                                                   \
		ERRORF("[-] PROGRAM ABORT : " x);                              \
		ERRORF("\n\tLocation : %s(), %s:%u\n\n", __FUNCTION__,         \
		       __FILE__, __LINE__);                                    \
		exit(EXIT_FAILURE);                                            \
	} while (0)

#define PFATAL(x...)                                                           \
	do {                                                                   \
		ERRORF("[-] SYSTEM ERROR : " x);                               \
		ERRORF("\n\tLocation : %s(), %s:%u\n", __FUNCTION__, __FILE__, \
		       __LINE__);                                              \
		perror("      OS message ");                                   \
		ERRORF("\n");                                                  \
		exit(EXIT_FAILURE);                                            \
	} while (0)

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1000000000ULL + (ts)->tv_nsec)

#define NSEC_TIMEVAL(ns)                                                       \
	(struct timeval)                                                       \
	{                                                                      \
		(ns) / 1000000000ULL, ((ns) % 1000000000ULL) / 1000ULL         \
	}
#define MSEC_NSEC(ms) ((ms)*1000000ULL)

struct icmp_packet
{
    uint8_t eth_dst[8];
    uint8_t eth_src[8];
    uint16_t eth_type;
    uint8_t ip_v_ihl,
            ip_tos;
    uint16_t    ip_length;
    uint16_t    ip_id;
    uint16_t   ip_flags_offset;
    uint8_t ip_ttl,
            ip_proto;
    uint16_t ip_chksum;
    uint8_t ip_src_addr[4],
            ip_dst_addr[4];
    uint8_t icmp_type,
            icmp_code;
    uint16_t    icmp_chksum,
            icmp_unused,
            icmp_mtu;
    uint8_t icmp_data[24 + 8]; // Maximum ip header length is 24 bytes
};

/* utils.c */
const char *optstring_from_long_options(const struct option *opt);
uint16_t add_checksum(const u_int8_t * buf, int length);
void build_packet(const struct icmp_packet * packet, u_int8_t **buf, int ip_length, int packet_length);
int set_core_dump(int enable);
const char *str_quote(const char *s);
const char *to_hex(const uint8_t *s, int len);
int signal_desc(int signal);

/* pcap.c */
pcap_t *setup_pcap(const char *iface, const char *bpf_filter, int snap_len,
		   struct pcap_stat *stats);
void unsetup_pcap(pcap_t *pcap, const char *iface, struct pcap_stat *stats);
int setup_raw(const char *iface);
const char *ip_to_string(const uint8_t *p, int p_len);

/* sched.c */
int taskset(int taskset_cpu);