// PMTUD
//
// Copyright (c) 2015 CloudFlare, Inc.

#include <getopt.h>
#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/time.h>

#include "pmtud.h"

const char *optstring_from_long_options(const struct option *opt)
{
	static char optstring[256] = {0};
	char *osp = optstring;

	for (; opt->name != NULL; opt++) {
		if (opt->flag == 0 && opt->val > 0 && opt->val < 256) {
			*osp++ = opt->val;
			switch (opt->has_arg) {
			case optional_argument:
				*osp++ = ':';
				*osp++ = ':';
				break;
			case required_argument:
				*osp++ = ':';
				break;
			}
		}
	}
	*osp++ = '\0';

	if (osp - optstring >= (int)sizeof(optstring)) {
		abort();
	}

	return optstring;
}

/**
  Returns the sum of the pairs of 2 bytes.
 **/
uint16_t add_checksum(const u_int8_t * buf, int length) {

    int i;
    uint16_t sum = 0, bytes;
    for(i = 1; i< length; i += 2) {
        bytes = (u_int8_t)buf[i] | ((u_int8_t)(buf[i - 1]) << 8);
        sum += bytes;
    }
    return sum;
}

/* @TODO : This is absolutely UGLY */
void build_packet(const struct icmp_packet * packet, u_int8_t **buf, int ip_payload_length, int packet_length) {
    *buf = malloc(sizeof(u_int8_t) * packet_length);
    int cursor = 0;

    memcpy(*buf, packet->eth_dst, 6);
    cursor += 6;

    memcpy(&(*buf)[cursor], packet->eth_src, 6);
    cursor += 6;

    memcpy(&(*buf)[cursor], &packet->eth_type, 2);
    cursor += 2;

    memcpy(&(*buf)[cursor], &packet->ip_v_ihl, 1);
    cursor += 1;

    memcpy(&(*buf)[cursor], &packet->ip_tos, 1);
    cursor += 1;

    memcpy(&(*buf)[cursor], &packet->ip_length, 2);
    cursor += 2;

    memcpy(&(*buf)[cursor], &packet->ip_id, 2);
    cursor += 2;

    memcpy(&(*buf)[cursor], &packet->ip_flags_offset, 2);
    cursor += 2;

    memcpy(&(*buf)[cursor], &packet->ip_ttl, 1);
    cursor += 1;

    memcpy(&(*buf)[cursor], &packet->ip_proto, 1);
    cursor += 1;

    memcpy(&(*buf)[cursor], &packet->ip_chksum, 2);
    cursor += 2;

    memcpy(&(*buf)[cursor], packet->ip_src_addr, 4);
    cursor += 4;

    memcpy(&(*buf)[cursor], packet->ip_dst_addr, 4);
    cursor += 4;

    memcpy(&(*buf)[cursor], &packet->icmp_type, 1);
    cursor += 1;

    memcpy(&(*buf)[cursor], &packet->icmp_code, 1);
    cursor += 1;

    memcpy(&(*buf)[cursor], &packet->icmp_chksum, 2);
    cursor += 2;

    memcpy(&(*buf)[cursor], &packet->icmp_unused, 2);
    cursor += 2;

    memcpy(&(*buf)[cursor], &packet->icmp_mtu, 2);
    cursor += 2;

    memcpy(&(*buf)[cursor], packet->icmp_data, ip_payload_length);
}

int set_core_dump(int enable)
{
	struct rlimit limit;
	limit.rlim_cur = limit.rlim_max = 0;
	if (enable) {
		limit.rlim_cur = limit.rlim_max = RLIM_INFINITY;
	}
	return setrlimit(RLIMIT_CORE, &limit);
}

const char *str_quote(const char *s)
{
	static char buf[1024];
	int r = snprintf(buf, sizeof(buf), "\"%.*s\"", (int)sizeof(buf) - 4, s);
	if (r >= (int)sizeof(buf)) {
		buf[sizeof(buf) - 1] = 0;
	}
	return buf;
}

const char *HEX_CHARS = "0123456789abcdef";

const char *to_hex(const uint8_t *s, int len)
{

	static char buf[1024 + 2];
	if (len > 512) {
		len = 512;
	}

	char *p = buf;
	int i;
	for (i = 0; i < len; i++) {
		p[i * 2] = HEX_CHARS[s[i] >> 4];
		p[i * 2 + 1] = HEX_CHARS[s[i] & 0x0f];
	}
	p[len * 2] = 0x00;
	return buf;
}

int signal_desc(int signal)
{
	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, signal);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
		PFATAL("sigprocmask(SIG_BLOCK, [%i])", signal);
	}

	int sfd = signalfd(-1, &mask, SFD_NONBLOCK);
	if (sfd == -1) {
		PFATAL("signalfd()");
	}
	return sfd;
}

const char **parse_argv(const char *str, char delim)
{
	int str_len = strlen(str);
	int i, items = 1;
	for (i = 0; i < str_len; i++) {
		if (str[i] == delim) {
			items += 1;
		}
	}

	char **argv = malloc(sizeof(char *) * (items + 1) + str_len + 1);
	char *nstr = (char *)&argv[items + 1];
	memcpy(nstr, str, str_len + 1);

	char delim_s[2] = {delim, '\x00'};
	char *s = nstr, *saveptr = NULL, **a = argv;

	for (;; s = NULL) {
		char *token = strtok_r(s, delim_s, &saveptr);
		if (token == NULL)
			break;

		a[0] = token;
		a += 1;
	}
	*a = NULL;

	return (const char **)argv;
}
