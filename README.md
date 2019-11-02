Path MTU Discovery Daemon
===============

## Overview

Devices behind VPN or other weird network links are unable to use [Path MTU Discovery](https://tools.ietf.org/html/rfc1191). This causes undesired fragmentation on the physical link between the device and the VPN endpoint.
If we know (i.e. calculate) the overhead added by the encapsulation of the prococol we use, we can directly listen to IPv4 packets with the DF (Don't Forward) bit set and send back ICMP type 3 code 4 messages with the correct MTU.
That is exaclty what PMTUDD (Path MTU Discovery Daemon) does.

Note: The source code for this project is derived from CloudFlare's [pmtud](https://github.com/cloudflare/pmtud), according to the project's license. I am incredibly thankful to have found this codebase from which I could build upon.

## Usage

```
$ ./pmtudd --help

Usage:

    pmtudd [options]

Path MTU Discovery Daemon listens for inbound IPv4 packets with the DF (Don't Fragment)
bit set and sends back ICMP code 3 messages related to MTU detection

Options:

  --iface              Network interface to listen on
  --src-rate           Pps limit from single source (default=1.1 pss)
  --iface-rate         Pps limit to send on a single interface (default=10.0 pps)
  --verbose            Print forwarded packets on screen
  --dry-run            Don't inject packets, just dry run
  --desired-mtu        The MTU to send back link
  --cpu                Pin to particular cpu
  --help               Print this message

Example:

    pmtudd --iface=eth2 --src-rate=1.1 --iface-rate=10.0 --desired-mtu=1420

```

## Building

    git submodule update --init --recursive
    make

## Additional information

pmtudd uses the following simple filter to match the approriate IPv4 packets:

    ip and ip[6] == 64 and greater {{MTU}}

It then filters out possibly invalid/bogus packets and ignores packets which have the same src and dst MAC addresses (this prevents an attacker from performing DoS attacks).
If the packet is valid, pmtudd crafts a new ICMP type 3 code 4 packet and sends it back to the address it received the original IPv4 packet from.

## Use case

This was developped as a reponse to the issue of running hosts behind a VXLAN over Wireguard tunnel. The hosts used a default MTU of 1500 and were unable to detect the appropriate MTU to use.
Using iptable rules on the wireless router to which they were connected in order to set the TCP MSS value was obviously not a good enough option and leaving all packets getting fragmented once sent on the physical link had a huge performance impact.

This could be useful in all situations where devices connect to a network which forwards all packets through a VPN tunnel (be it IPSec, Wireguard, OpenVPN or any other) and where the physical MTU of the underlying network cannot be modified.