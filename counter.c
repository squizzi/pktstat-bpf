// @license
// Copyright (C) 2024  Dinko Korunic
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_ENTRIES 4096
#define MAX_DNS_NAME_LENGTH 256

#define s6_addr in6_u.u6_addr8
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
#define inet_num sk.__sk_common.skc_num

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define TC_ACT_UNSPEC -1
#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16
#define IPPROTO_ICMPV6 58

#define OK 1
#define NOK 0

#define DNS_CACHE_HIT 1
#define DNS_CACHE_MISS 2

#define DNS_RESPONSE_THRESHOLD 1000000 // 1ms in nanoseconds

// Map key struct for IP traffic
typedef struct statkey_t {
  struct in6_addr srcip;    // source IPv6 address
  struct in6_addr dstip;    // destination IPv6 address
  __u16 src_port;           // source port
  __u16 dst_port;           // destination port
  __u8 proto;               // transport protocol
  pid_t pid;                // process ID
  char comm[TASK_COMM_LEN]; // process command
} statkey;

// Map value struct with counters
typedef struct statvalue_t {
  __u64 packets; // packets ingress + egress
  __u64 bytes;   // bytes ingress + egress
} statvalue;

// Map definition
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH); // LRU hash requires 4.10 kernel
  __uint(max_entries, MAX_ENTRIES);
  __type(key, statkey);
  __type(value, statvalue);
} pkt_count SEC(".maps");

// DNS query types we care about
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_CNAME 5

// Structure to hold DNS query information
struct dns_query {
    __u32 pid;
    __u16 qtype;
    char qname[MAX_DNS_NAME_LENGTH];
    __u64 timestamp;
};

// Structure to hold DNS response information
struct dns_response {
    __u32 pid;
    __u16 qtype;
    char qname[MAX_DNS_NAME_LENGTH];
    union {
        __be32 ipv4;
        struct in6_addr ipv6;
    } addr;
    __u64 timestamp;
};

// Map to store DNS queries
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);  // Use transaction ID as key
    __type(value, struct dns_query);
} dns_queries SEC(".maps");

// Map to store DNS responses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);  // Use transaction ID as key
    __type(value, struct dns_response);
} dns_responses SEC(".maps");

// Structure to hold DNS cache event information
struct dns_cache_event {
    __u32 pid;
    __u8 event_type;  // DNS_CACHE_HIT or DNS_CACHE_MISS
    char qname[MAX_DNS_NAME_LENGTH];
    __u64 timestamp;
};

// Map to store DNS cache events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct dns_cache_event);
} dns_cache_events SEC(".maps");

// Map to store DNS query timestamps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);  // PID as key
    __type(value, __u64); // Timestamp
} dns_query_timestamps SEC(".maps");

// Add per-CPU array maps for large structures
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_cache_event);
} dns_event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct dns_response);
} dns_response_heap SEC(".maps");

// IPv4-mapped IPv6 address prefix (for V4MAPPED conversion)
static const __u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

/**
 * Process an IPv4 packet and populate the key with the relevant information.
 *
 * @param ip4 pointer to the start of the IPv4 header
 * @param data_end pointer to the end of the packet data
 * @param key pointer to the statkey structure to be populated
 *
 * @return OK if the packet was processed successfully, NOK otherwise
 *
 * @throws none
 */
static inline int process_ip4(struct iphdr *ip4, void *data_end, statkey *key) {
  // validate IPv4 size
  if ((void *)ip4 + sizeof(*ip4) > data_end) {
    return NOK;
  }

  // convert to V4MAPPED address
  __builtin_memcpy(key->srcip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->srcip.s6_addr + sizeof(ip4in6), &ip4->saddr,
                   sizeof(ip4->saddr));

  // convert to V4MAPPED address
  __builtin_memcpy(key->dstip.s6_addr, ip4in6, sizeof(ip4in6));
  __builtin_memcpy(key->dstip.s6_addr + sizeof(ip4in6), &ip4->daddr,
                   sizeof(ip4->daddr));

  key->proto = ip4->protocol;

  switch (ip4->protocol) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = (void *)ip4 + sizeof(*ip4);

    // validate TCP size
    if ((void *)tcp + sizeof(*tcp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);

    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = (void *)ip4 + sizeof(*ip4);

    // validate UDP size
    if ((void *)udp + sizeof(*udp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);

    break;
  }
  case IPPROTO_ICMP: {
    struct icmphdr *icmp = (void *)ip4 + sizeof(*ip4);

    // validate ICMP size
    if ((void *)icmp + sizeof(*icmp) > data_end) {
      return NOK;
    }

    // store ICMP type in src port
    key->src_port = icmp->type;
    // store ICMP code in dst port
    key->dst_port = icmp->code;

    break;
  }
  }

  return OK;
}

/**
 * Process an IPv6 packet and extract relevant information to populate
 * the key.
 *
 * @param ip6 pointer to the start of the IPv6 header
 * @param data_end pointer to the end of the packet data
 * @param key pointer to the statkey structure to be populated
 *
 * @return OK if the packet was successfully processed, NOK otherwise
 *
 * @throws none
 */
static inline int process_ip6(struct ipv6hdr *ip6, void *data_end,
                              statkey *key) {
  // validate IPv6 size
  if ((void *)ip6 + sizeof(*ip6) > data_end) {
    return NOK;
  }

  // IPv6 copy of source IP, destination IP and transport protocol
  key->srcip = ip6->saddr;
  key->dstip = ip6->daddr;
  key->proto = ip6->nexthdr;

  switch (ip6->nexthdr) {
  case IPPROTO_TCP: {
    struct tcphdr *tcp = (void *)ip6 + sizeof(*ip6);

    // validate TCP size
    if ((void *)tcp + sizeof(*tcp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(tcp->source);
    key->dst_port = bpf_ntohs(tcp->dest);

    break;
  }
  case IPPROTO_UDP: {
    struct udphdr *udp = (void *)ip6 + sizeof(*ip6);

    // validate UDP size
    if ((void *)udp + sizeof(*udp) > data_end) {
      return NOK;
    }

    key->src_port = bpf_ntohs(udp->source);
    key->dst_port = bpf_ntohs(udp->dest);

    break;
  }
  case IPPROTO_ICMPV6: {
    struct icmp6hdr *icmp = (void *)ip6 + sizeof(*ip6);

    // validate ICMPv6 size
    if ((void *)icmp + sizeof(*icmp) > data_end) {
      return NOK;
    }

    // store ICMP type in src port
    key->src_port = icmp->icmp6_type;
    // store ICMP code in dst port
    key->dst_port = icmp->icmp6_code;

    break;
  }
  }

  return OK;
}

/**
 * Process the Ethernet header and extract relevant information to populate
 * the key.
 *
 * @param data pointer to the start of the Ethernet header
 * @param data_end pointer to the end of the packet data
 * @param pkt_len length of the packet
 *
 * @return none
 *
 * @throws none
 */
static inline void process_eth(void *data, void *data_end, __u64 pkt_len) {
  struct ethhdr *eth = data;

  // validate Ethernet size
  if ((void *)eth + sizeof(*eth) > data_end) {
    return;
  }

  // initialize key
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  // process only IPv4 and IPv6
  switch (bpf_ntohs(eth->h_proto)) {
  case ETH_P_IP: {
    struct iphdr *ip4 = (void *)eth + sizeof(*eth);

    if (process_ip4(ip4, data_end, &key) == NOK) {
      return;
    }

    break;
  }
  case ETH_P_IPV6: {
    struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);

    if (process_ip6(ip6, data_end, &key) == NOK) {
      return;
    }

    break;
  }
  default:
    return;
  }

  // lookup value in hash
  statvalue *val = (statvalue *)bpf_map_lookup_elem(&pkt_count, &key);
  if (val) {
    // atomic XADD, doesn't need bpf_spin_lock()
    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, pkt_len);
  } else {
    statvalue initval = {.packets = 1, .bytes = pkt_len};

    bpf_map_update_elem(&pkt_count, &key, &initval, BPF_NOEXIST);
  }
}

/**
 * Process the packet for traffic control and take necessary actions.
 *
 * @param skb pointer to the packet buffer
 *
 * @return TC_ACT_UNSPEC
 *
 * @throws none
 */
static inline void tc_process_packet(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  process_eth(data, data_end, skb->len);
}

/**
 * Process the packet for XDP (eXpress Data Path) and take necessary actions.
 *
 * @param ctx pointer to the XDP context
 *
 * @return XDP_PASS
 *
 * @throws none
 */
static inline void xdp_process_packet(struct xdp_md *xdp) {
  void *data = (void *)(long)xdp->data;
  void *data_end = (void *)(long)xdp->data_end;

  process_eth(data, data_end, data_end - data);
}

/**
 * This function is a BPF program entry point for processing packets using
 * XDP (eXpress Data Path). It invokes the xdp_process_packet function to
 * handle the packet specified by the xdp parameter.
 *
 * @param xdp pointer to the XDP context
 *
 * @return XDP_PASS to indicate that the packet should be passed to the
 *         next processing stage in the network stack
 *
 * @throws none
 */
SEC("xdp")
int xdp_count_packets(struct xdp_md *xdp) {
  xdp_process_packet(xdp);

  return XDP_PASS;
}

/**
 * Process a packet for Traffic Control and update statistics.
 *
 * This function is a BPF program entry point for packet processing using
 * Traffic Control (TC) hooks. It invokes the tc_process_packet function
 * to handle the packet specified by the skb parameter.
 *
 * @param skb pointer to the packet buffer
 *
 * @return TC_ACT_UNSPEC to indicate no specific TC action is taken
 *
 * @throws none
 */
SEC("tc")
int tc_count_packets(struct __sk_buff *skb) {
  tc_process_packet(skb);

  return TC_ACT_UNSPEC;
}

/**
 * Process TCP socket information and populate the key structure with
 * extracted data.
 *
 * @param sk pointer to the socket structure
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the socket
 *
 * This function reads the socket's address family and based on whether it is
 * IPv4 or IPv6, it extracts the source and destination IP addresses and
 * ports. It also sets the protocol to TCP and assigns the provided process ID
 * to the key.
 *
 * The function handles both IPv4 and IPv6 addresses by converting them to an
 * IPv6-mapped format for uniformity.
 *
 * @throws none
 */
static inline void process_tcp(struct sock *sk, statkey *key, pid_t pid) {
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);

  switch (family) {
  case AF_INET: {
    // convert to V4MAPPED address
    __be32 ip4_src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key->srcip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->srcip.s6_addr32[3], &ip4_src, sizeof(ip4_src));

    // convert to V4MAPPED address
    __be32 ip4_dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key->dstip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->dstip.s6_addr32[3], &ip4_dst, sizeof(ip4_dst));

    break;
  }
  case AF_INET6: {
    BPF_CORE_READ_INTO(&key->srcip, sk, __sk_common.skc_v6_rcv_saddr);
    BPF_CORE_READ_INTO(&key->dstip, sk, __sk_common.skc_v6_daddr);

    break;
  }
  default: {
    return;
  }
  }

  __u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
  if (sport == 0) {
    struct inet_sock *isk = (struct inet_sock *)sk;
    BPF_CORE_READ_INTO(&sport, isk, inet_sport);
  }
  key->src_port = bpf_ntohs(sport);
  key->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  key->proto = IPPROTO_TCP;
  key->pid = pid;
}

/**
 * Process UDP socket information from a sk_buff and populate the key
 * structure.
 *
 * @param skb pointer to the socket buffer containing the UDP packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IP addresses and ports from
 * the UDP packet, taking into account both IPv4 and IPv6 headers. It stores
 * these details in the provided statkey structure, along with the protocol
 * type set to UDP and the associated process ID.
 *
 * @throws none
 */
static inline void process_udp_recv(struct sk_buff *skb, statkey *key,
                                    pid_t pid) {
  struct udphdr *udphdr =
      (struct udphdr *)(BPF_CORE_READ(skb, head) +
                        BPF_CORE_READ(skb, transport_header));

  __u16 proto = BPF_CORE_READ(skb, protocol);

  switch (bpf_ntohs(proto)) {
  case ETH_P_IP: {
    struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                           BPF_CORE_READ(skb, network_header));

    // convert to V4MAPPED address
    __be32 ip4_src = BPF_CORE_READ(iphdr, saddr);
    key->srcip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->srcip.s6_addr32[3], &ip4_src, sizeof(ip4_src));

    // convert to V4MAPPED address
    __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
    key->dstip.s6_addr16[5] = bpf_htons(0xffff);
    __builtin_memcpy(&key->dstip.s6_addr32[3], &ip4_dst, sizeof(ip4_dst));
    break;
  }
  case ETH_P_IPV6: {
    struct ipv6hdr *iphdr =
        (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                           BPF_CORE_READ(skb, network_header));

    BPF_CORE_READ_INTO(&key->srcip, iphdr, saddr);
    BPF_CORE_READ_INTO(&key->dstip, iphdr, daddr);

    break;
  }
  default:
    return;
  }

  key->src_port = bpf_ntohs(BPF_CORE_READ(udphdr, source));
  key->dst_port = bpf_ntohs(BPF_CORE_READ(udphdr, dest));

  key->proto = IPPROTO_UDP;
  key->pid = pid;
}

/**
 * Process an ICMPv4 packet and populate the key with the relevant information.
 *
 * @param skb pointer to the socket buffer containing the ICMPv4 packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IP addresses and ICMP type
 * and code from the ICMPv4 packet, taking into account the IPv4 header. It
 * stores these details in the provided statkey structure, along with the
 * protocol type set to ICMPv4 and the associated process ID.
 *
 * @throws none
 */
static inline size_t process_icmp4(struct sk_buff *skb, statkey *key,
                                   pid_t pid) {
  struct icmphdr *icmphdr =
      (struct icmphdr *)(BPF_CORE_READ(skb, head) +
                         BPF_CORE_READ(skb, transport_header));
  struct iphdr *iphdr = (struct iphdr *)(BPF_CORE_READ(skb, head) +
                                         BPF_CORE_READ(skb, network_header));

  // convert to V4MAPPED address
  __be32 ip4_src = BPF_CORE_READ(iphdr, saddr);
  key->srcip.s6_addr16[5] = bpf_htons(0xffff);
  __builtin_memcpy(&key->srcip.s6_addr32[3], &ip4_src, sizeof(ip4_src));

  // convert to V4MAPPED address
  __be32 ip4_dst = BPF_CORE_READ(iphdr, daddr);
  key->dstip.s6_addr16[5] = bpf_htons(0xffff);
  __builtin_memcpy(&key->dstip.s6_addr32[3], &ip4_dst, sizeof(ip4_dst));

  // store ICMP type in src port
  key->src_port = BPF_CORE_READ(icmphdr, type);
  // store ICMP code in dst port
  key->dst_port = BPF_CORE_READ(icmphdr, code);

  key->proto = IPPROTO_ICMP;
  key->pid = pid;

  size_t msglen = bpf_ntohs(BPF_CORE_READ(iphdr, tot_len)) -
                  BPF_CORE_READ_BITFIELD_PROBED(iphdr, ihl) * 4;

  return msglen;
}

/**
 * Process an ICMPv6 packet and populate the key with the relevant information.
 *
 * @param skb pointer to the socket buffer containing the ICMPv6 packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IP addresses and ICMPv6 type
 * and code from the ICMPv6 packet, taking into account the IPv6 header. It
 * stores these details in the provided statkey structure, along with the
 * protocol type set to ICMPv6 and the associated process ID. It also returns
 * the length of the ICMPv6 message payload.
 *
 * @return the length of the ICMPv6 message payload
 * @throws none
 */

static inline size_t process_icmp6(struct sk_buff *skb, statkey *key,
                                   pid_t pid) {
  struct icmp6hdr *icmphdr =
      (struct icmp6hdr *)(BPF_CORE_READ(skb, head) +
                          BPF_CORE_READ(skb, transport_header));

  struct ipv6hdr *iphdr =
      (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                         BPF_CORE_READ(skb, network_header));

  BPF_CORE_READ_INTO(&key->srcip, iphdr, saddr);
  BPF_CORE_READ_INTO(&key->dstip, iphdr, daddr);

  // store ICMP type in src port
  key->src_port = BPF_CORE_READ(icmphdr, icmp6_type);
  // store ICMP code in dst port
  key->dst_port = BPF_CORE_READ(icmphdr, icmp6_code);

  key->proto = IPPROTO_ICMPV6;
  key->pid = pid;

  size_t msglen = bpf_ntohs(BPF_CORE_READ(iphdr, payload_len));

  return msglen;
}

/**
 * Process UDP socket information from a sk_buff and populate the key
 * structure.
 *
 * @param skb pointer to the socket buffer containing the UDP packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IP addresses and ports from
 * the UDP packet, taking into account both IPv4 and IPv6 headers. It stores
 * these details in the provided statkey structure, along with the protocol
 * type set to UDP and the associated process ID. It also returns the length
 * of the UDP message.
 *
 * @throws none
 */
static inline size_t process_udp_send(struct sk_buff *skb, statkey *key,
                                      pid_t pid) {
  struct udphdr *udphdr =
      (struct udphdr *)(BPF_CORE_READ(skb, head) +
                        BPF_CORE_READ(skb, transport_header));

  process_udp_recv(skb, key, pid);
  size_t msglen = BPF_CORE_READ(udphdr, len);

  return msglen;
}

#if 0
/**
 * Process raw ICMP socket information for IPv4 and populate the key structure.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the message header structure containing the packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IPv4 addresses and ICMP type
 * and code from the raw socket message. It populates the provided statkey
 * structure with these details, converting IPv4 addresses to IPv6-mapped
 * format. The function only processes messages with the ICMP protocol.
 *
 * @throws none
 */

static inline void process_raw_sendmsg4(struct sock *sk, struct msghdr *msg,
                                        statkey *key, pid_t pid) {
  struct inet_sock *isk = (struct inet_sock *)sk;
  struct sockaddr_in *sin = (struct sockaddr_in *)BPF_CORE_READ(msg, msg_name);

  // raw sockets have the protocol number in inet_num
  __u16 proto = BPF_CORE_READ(isk, inet_num);
  if (proto != IPPROTO_ICMP) {
    return;
  }

  // convert to V4MAPPED address
  __be32 ip4_src = BPF_CORE_READ(isk, inet_saddr);
  key->srcip.s6_addr16[5] = bpf_htons(0xffff);
  __builtin_memcpy(&key->srcip.s6_addr32[3], &ip4_src, sizeof(ip4_src));

  // convert to V4MAPPED address
  __be32 ip4_dst = BPF_CORE_READ(sin, sin_addr.s_addr);
  key->dstip.s6_addr16[5] = bpf_htons(0xffff);
  __builtin_memcpy(&key->dstip.s6_addr32[3], &ip4_dst, sizeof(ip4_dst));

  struct iovec *iov = (struct iovec *)BPF_CORE_READ(msg, msg_iter.__iov);
  struct icmphdr *icmphdr = (struct icmphdr *)BPF_CORE_READ(iov, iov_base);

  // store ICMP type in src port
  key->src_port = BPF_CORE_READ(icmphdr, type);
  // store ICMP code in dst port
  key->dst_port = BPF_CORE_READ(icmphdr, code);

  key->proto = IPPROTO_ICMP;
  key->pid = pid;
}
#endif

#if 0
/**
 * Process raw ICMP socket information for IPv6 and populate the key structure.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the message header structure containing the packet
 * @param key pointer to the statkey structure to be populated
 * @param pid process ID associated with the packet
 *
 * This function extracts source and destination IPv6 addresses and ICMPv6 type
 * and code from the raw socket message. It populates the provided statkey
 * structure with these details. The function only processes messages with the
 * ICMPv6 protocol.
 *
 * @throws none
 */

static inline void process_raw_sendmsg6(struct sock *sk, struct msghdr *msg,
                                        statkey *key, pid_t pid) {
  struct inet_sock *isk = (struct inet_sock *)sk;
  struct sockaddr_in6 *sin =
      (struct sockaddr_in6 *)BPF_CORE_READ(msg, msg_name);

  // raw sockets have the protocol number in inet_num
  __u16 proto = BPF_CORE_READ(isk, inet_num);
  if (proto != IPPROTO_ICMPV6) {
    return;
  }

  BPF_CORE_READ_INTO(&key->srcip, isk, inet_saddr);
  BPF_CORE_READ_INTO(&key->dstip, sin, sin6_addr);

  struct iovec *iov = (struct iovec *)BPF_CORE_READ(msg, msg_iter.__iov);
  struct icmp6hdr *icmphdr = (struct icmp6hdr *)BPF_CORE_READ(iov, iov_base);

  // store ICMP type in src port
  key->src_port = BPF_CORE_READ(icmphdr, icmp6_type);
  // store ICMP code in dst port
  key->dst_port = BPF_CORE_READ(icmphdr, icmp6_code);

  key->proto = IPPROTO_ICMPV6;
  key->pid = pid;
}
#endif

/**
 * Update the packet and byte counters for the given key in the packet count
 * map. If the key is not present, it is inserted with an initial value of 1
 * packet and the given size in bytes. If the key is already present, the
 * packet and byte counters are atomically incremented.
 *
 * @param key pointer to the statkey structure containing the key to be
 * updated
 * @param size size of the packet to be counted
 *
 * @throws none
 */
static inline void update_val(statkey *key, size_t size) {
  // lookup value in hash
  statvalue *val = (statvalue *)bpf_map_lookup_elem(&pkt_count, key);
  if (val) {
    // atomic XADD, doesn't need bpf_spin_lock()
    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, size);
  } else {
    statvalue initval = {.packets = 1, .bytes = size};

    bpf_map_update_elem(&pkt_count, key, &initval, BPF_NOEXIST);
  }
}

/**
 * Hook function for kprobe on tcp_sendmsg function.
 *
 * Populates the statkey structure with information from the UDP packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the msghdr structure
 * @param size size of the packet to be counted
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  process_tcp(sk, &key, pid);
  update_val(&key, size);

  return 0;
}

/**
 * Hook function for kprobe on tcp_cleanup_rbuf function.
 *
 * Populates the statkey structure with information from the socket and the
 * process ID associated with the socket, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param copied size of the packet to be counted
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied) {
  if (copied <= 0) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  process_tcp(sk, &key, pid);
  update_val(&key, copied);

  return 0;
}

/**
 * Hook function for kprobe on ip_send_skb function.
 *
 * Populates the statkey structure with information from the socket and the
 * process ID associated with the socket, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param net pointer to the network namespace structure
 * @param skb pointer to the socket buffer
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/ip_send_skb")
int BPF_KPROBE(ip_send_skb, struct net *net, struct sk_buff *skb) {
  __u16 protocol = BPF_CORE_READ(skb, protocol);
  if (protocol != IPPROTO_UDP) {
    return 0;
  }

  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  size_t msglen = process_udp_send(skb, &key, pid);
  update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on skb_consume_udp function.
 *
 * Populates the statkey structure with information from the UDP packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param skb pointer to the socket buffer containing the UDP packet
 * @param len length of the UDP message
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  process_udp_recv(skb, &key, pid);
  update_val(&key, len);

  return 0;
}

/**
 * Hook function for kprobe on __icmp_send function.
 *
 * Populates the statkey structure with information from the ICMPv4 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param skb pointer to the socket buffer containing the ICMPv4 packet
 * @param type type of ICMPv4 packet
 * @param code code of ICMPv4 packet
 * @param info additional information for the ICMPv4 packet
 * @param opt pointer to the ip_options structure
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/__icmp_send")
int BPF_KPROBE(__icmp_send, struct sk_buff *skb, __u8 type, __u8 code,
               __be32 info, const struct ip_options *opt) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  size_t msglen = process_icmp4(skb, &key, pid);
  update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on icmp6_send function.
 *
 * Populates the statkey structure with information from the ICMPv6 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param skb pointer to the socket buffer containing the ICMPv6 packet
 * @param type type of ICMPv6 packet
 * @param code code of ICMPv6 packet
 * @param info additional information for the ICMPv6 packet
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/icmp6_send")
int BPF_KPROBE(icmp6_send, struct sk_buff *skb, __u8 type, __u8 code,
               __u32 info) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  size_t msglen = process_icmp6(skb, &key, pid);
  update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on icmp_rcv function.
 *
 * Populates the statkey structure with information from the ICMP packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param skb pointer to the socket buffer containing the ICMP packet
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/icmp_rcv")
int BPF_KPROBE(icmp_rcv, struct sk_buff *skb) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  size_t msglen = process_icmp4(skb, &key, pid);
  update_val(&key, msglen);

  return 0;
}

/**
 * Hook function for kprobe on icmpv6_rcv function.
 *
 * Populates the statkey structure with information from the ICMPv6 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param skb pointer to the socket buffer containing the ICMPv6 packet
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/icmpv6_rcv")
int BPF_KPROBE(icmpv6_rcv, struct sk_buff *skb) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  size_t msglen = process_icmp6(skb, &key, pid);
  update_val(&key, msglen);

  return 0;
}

#if 0
/**
 * Hook function for kprobe on raw_sendmsg function.
 *
 * Populates the statkey structure with information from the raw IPv4 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the msghdr structure
 * @param len size of the message
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/raw_sendmsg")
int BPF_KPROBE(raw_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  process_raw_sendmsg4(sk, msg, &key, pid);
  update_val(&key, len);

  return 0;
}
#endif

#if 0
/**
 * Hook function for kprobe on rawv6_sendmsg function.
 *
 * Populates the statkey structure with information from the raw IPv6 packet and
 * the process ID associated with the packet, and updates the packet and byte
 * counters in the packet count map.
 *
 * @param sk pointer to the socket structure
 * @param msg pointer to the msghdr structure
 * @param len size of the message
 *
 * @return 0
 *
 * @throws none
 */
SEC("kprobe/rawv6_sendmsg")
int BPF_KPROBE(rawv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
  statkey key;
  __builtin_memset(&key, 0, sizeof(key));

  pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  if (pid > 0) {
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
  }

  process_raw_sendmsg6(sk, msg, &key, pid);
  update_val(&key, len);

  return 0;
}
#endif

// Fix parse_dns_name function
static __always_inline int parse_dns_name(void *data, void *data_end, 
                                        char *name, int max_len) {
    unsigned char *cursor = data;
    char *name_cursor = name;
    int len = 0;
    int label_len;

    // Fix pointer comparison by casting to uintptr_t
    while ((void *)(cursor + 1) <= data_end) {
        label_len = *cursor;
        if (label_len == 0)
            break;

        cursor++;
        // Fix pointer comparison
        if ((void *)(cursor + label_len) > data_end)
            return -1;

        if (len + label_len + 1 > max_len)
            return -1;

        if (len > 0) {
            *name_cursor = '.';
            name_cursor++;
            len++;
        }

        if (bpf_probe_read_kernel(name_cursor, label_len, cursor) < 0)
            return -1;
            
        name_cursor += label_len;
        len += label_len;
        cursor += label_len;
    }

    if (len < max_len)
        name[len] = '\0';

    return len;
}

// DNS header structure
struct dns_header {
    __u16 transaction_id;
    __u16 flags;
    __u16 questions;
    __u16 answer_rrs;
    __u16 authority_rrs;
    __u16 additional_rrs;
};

// DNS question structure
struct dns_question {
    __u16 qtype;
    __u16 qclass;
};

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(dns_recvmsg, struct sock *sk, struct msghdr *msg) {
    if (!sk || !msg)
        return 0;

    // Get destination port safely
    __u16 dport;
    if (bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport) < 0)
        return 0;
    
    // Only process DNS traffic (port 53)
    if (bpf_ntohs(dport) != 53)
        return 0;

    // Get current PID/TID
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 current_time = bpf_ktime_get_ns();

    // Get pointer to per-CPU response structure
    __u32 zero = 0;
    struct dns_query *query = bpf_map_lookup_elem(&dns_event_heap, &zero);
    if (!query)
        return 0;

    // Initialize query
    query->pid = pid;
    query->timestamp = current_time;

    // Try to get the DNS name from the packet
    void *data = NULL;
    size_t len = 0;
    
    // Read base and len safely using BPF_CORE_READ
    data = BPF_CORE_READ(msg, msg_iter.kvec->iov_base);
    len = BPF_CORE_READ(msg, msg_iter.kvec->iov_len);

    // Ensure we have enough data for DNS header
    if (len >= sizeof(struct dns_header)) {
        struct dns_header hdr;
        if (bpf_probe_read_kernel(&hdr, sizeof(hdr), data) == 0) {
            // Skip DNS header to get to the question section
            unsigned char *question = data + sizeof(struct dns_header);
            
            // Parse the DNS name
            if (parse_dns_name(question, data + len, query->qname, sizeof(query->qname)) < 0) {
                // If parsing fails, use process name as fallback
                bpf_get_current_comm(query->qname, sizeof(query->qname));
            }
        }
    }

    // If we couldn't get the DNS name, use process name as fallback
    if (query->qname[0] == '\0') {
        bpf_get_current_comm(query->qname, sizeof(query->qname));
    }

    // Store query in map
    bpf_map_update_elem(&dns_queries, &pid, query, BPF_ANY);

    // Store timestamp for cache detection
    bpf_map_update_elem(&dns_query_timestamps, &pid, &current_time, BPF_ANY);

    return 0;
}

// Update DNS send message handler to preserve the DNS name
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(dns_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    if (!sk)
        return 0;

    // Get source port safely
    __u16 sport;
    if (bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num) < 0)
        return 0;
    
    // Only process DNS traffic (port 53)
    if (sport != 53)
        return 0;

    // Get current PID/TID
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 current_time = bpf_ktime_get_ns();

    // Check if we have a timestamp for this PID
    __u64 *query_time = bpf_map_lookup_elem(&dns_query_timestamps, &pid);
    if (!query_time)
        return 0;

    // Calculate response time
    __u64 response_time = current_time - *query_time;
    
    // Get pointer to per-CPU event structure
    __u32 zero = 0;
    struct dns_cache_event *event = bpf_map_lookup_elem(&dns_event_heap, &zero);
    if (!event)
        return 0;

    // Initialize event
    event->pid = pid;
    event->timestamp = current_time;
    event->event_type = (response_time < DNS_RESPONSE_THRESHOLD) ? DNS_CACHE_HIT : DNS_CACHE_MISS;

    // Try to get the original query name
    struct dns_query *orig_query = bpf_map_lookup_elem(&dns_queries, &pid);
    if (orig_query) {
        __builtin_memcpy(event->qname, orig_query->qname, sizeof(event->qname));
    } else {
        // Fallback to process name if query not found
        bpf_get_current_comm(event->qname, sizeof(event->qname));
    }

    // Store cache event
    bpf_map_update_elem(&dns_cache_events, &pid, event, BPF_ANY);

    // Get pointer to per-CPU response structure
    struct dns_response *response = bpf_map_lookup_elem(&dns_response_heap, &zero);
    if (response) {
        response->pid = pid;
        response->timestamp = current_time;
        __builtin_memcpy(response->qname, event->qname, sizeof(response->qname));
        bpf_map_update_elem(&dns_responses, &pid, response, BPF_ANY);
    }

    // Clean up
    bpf_map_delete_elem(&dns_query_timestamps, &pid);
    bpf_map_delete_elem(&dns_queries, &pid);

    return 0;
}

// Function to check DNS cache status
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(dns_cache_lookup, struct sock *sk, struct msghdr *msg) {
    if (!sk)
        return 0;

    // Get destination port safely using BPF_CORE_READ
    __u16 dport;
    if (bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport) < 0)
        return 0;
    
    // Only process DNS traffic (port 53)
    if (bpf_ntohs(dport) != 53)
        return 0;

    // Get current PID/TID and timestamp
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 current_time = bpf_ktime_get_ns();

    // Get pointer to per-CPU event structure
    __u32 zero = 0;
    struct dns_cache_event *event = bpf_map_lookup_elem(&dns_event_heap, &zero);
    if (!event)
        return 0;

    // Initialize event
    event->pid = pid;
    event->timestamp = current_time;
    event->event_type = DNS_CACHE_MISS;  // Default to cache miss

    // Get process name
    bpf_get_current_comm(event->qname, sizeof(event->qname));

    // Check if we have a recent query from this PID
    __u64 *last_query = bpf_map_lookup_elem(&dns_query_timestamps, &pid);
    if (last_query) {
        __u64 time_diff = current_time - *last_query;
        if (time_diff < DNS_RESPONSE_THRESHOLD) {
            event->event_type = DNS_CACHE_HIT;
        }
    }

    // Store the event
    bpf_map_update_elem(&dns_cache_events, &pid, event, BPF_ANY);
    
    // Update timestamp
    bpf_map_update_elem(&dns_query_timestamps, &pid, &current_time, BPF_ANY);

    return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
