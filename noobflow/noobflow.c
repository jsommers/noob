// noobflow.c - Used to instantiate BPF program in noobflow.py
// Nolan Rudolph
//
// NOTE: This module cannot have...
//         1. Loops
//         2. Access outside of contextual (ctx) memory
//         3. Excessive use of eBPF instructions

/* PREPROCESSORS */
#define BPF_LICENSE GPL
#define KBUILD_MODNAME "noobflow"
#include <linux/bpf.h>
#include <linux/inet.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#define ICMP 1
#define TCP 6
#define UDP 17

/* TYPEDEFS */
typedef unsigned char u_char;

typedef struct flow_attrs
{
  uint16_t l2_proto;
  uint8_t l4_proto;
  __be32 src_ip;
  __be32 dst_ip;
  __be16 src_port;
  __be16 dst_port;
} flow_attrs;

typedef struct flow_accms
{
  u64 start;
  u64 end;
  uint64_t packets;
  uint64_t bytes;
} flow_accms;

/* BPF MAPS */
BPF_TABLE("percpu_hash", struct flow_attrs, struct flow_accms, flows0, MAPSIZE);
BPF_TABLE("percpu_hash", struct flow_attrs, struct flow_accms, flows1, MAPSIZE);
BPF_PROG_ARRAY(parse_layer3, 7);

/* CODE */
int xdp_parser(struct xdp_md *ctx)
{
  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Accomplishes NOTE 2
  if (data + sizeof(struct ethhdr) > data_end)
  {
    return XDP_DROP;
  }

  // Cast Ethernet Header to data
  struct ethhdr *ether = (struct ethhdr *)data;

  // Extract Little Endian Ethertype
  __be16 ether_be = ether -> h_proto;
  // IPv4 Packet Handling
  if (ether_be == htons(ETH_P_IP))
  {
    parse_layer3.call(ctx, 4);
    return XDP_DROP;
  }
  // IPv6 Packet Handling
  else if (ether_be == htons(ETH_P_IPV6))
  {
    parse_layer3.call(ctx, 6);
    return XDP_DROP;
  }
  // VLAN Packet Handling
  else if (ether_be == htons(ETH_P_8021Q) || ether_be == htons(ETH_P_8021AD))
  {
    bpf_trace_printk("Received Ethertype VLAN!");
  }
  // Other Packet Handling
  else
  {
    bpf_trace_printk("IPv4/IPv6/VLAN Ethertypes were not hit!");
  }

  return XDP_DROP;
}

// don't do anything; just let packets pass
int null_parser(struct xdp_md *ctx) 
{
    return XDP_PASS;
}

// (IPv4 i.e. parse_layer3.call(ctx, 4)) Passed context via program array
int parse_ipv4_flows0(struct xdp_md *ctx) 
{
  // Packet to store in hash
  flow_attrs p = {0, 0, 0, 0, 0, 0};

  // Offset for memory boundary checks
  int offset = sizeof(struct ethhdr);

  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Make sure the data is accessible (see note 2 above)
  if (data + offset + sizeof(struct iphdr) > data_end) 
  {
    return XDP_DROP;
  }

  // Fix IP Header pointer to correct location
  struct iphdr *iph = (struct iphdr *)(data + offset);
  offset += sizeof(struct iphdr);

  // # of bytes for accumulator variables
  uint16_t bytes = (ctx -> data_end) - (ctx -> data);

  // Store L2 + L3 Protocol, src_ip, dst_ip, and #bytes
  p.l2_proto = ETH_P_IP;
  __builtin_memcpy(&p.src_ip, &(iph -> saddr), sizeof(__be32));
  __builtin_memcpy(&p.dst_ip, &(iph -> daddr), sizeof(__be32));

  // Get L4 protocol
  u_short proto = iph -> protocol;

  // Put layer 4 attributes in flow_attrs
  if (proto == ICMP && (data + offset + sizeof(struct icmphdr) < data_end))
  {
    struct icmphdr *icmph = (struct icmphdr *)(data + offset);

    // Store L4 Protocol, src_port (type), and dst_port (code)
    p.l4_proto = ICMP;
    
    __builtin_memcpy(&p.src_port, &(icmph -> type), sizeof(uint8_t));
    __builtin_memcpy(&p.dst_port, &(icmph -> code), sizeof(uint8_t));
  }
  else if (proto == TCP && (data + offset + sizeof(struct tcphdr) < data_end))
  {
    struct tcphdr *tcph = (struct tcphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = TCP;

    __builtin_memcpy(&p.src_port, &(tcph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(tcph -> dest), sizeof(__be16));
  }
  else if (proto == UDP && (data + offset + sizeof(struct udphdr) < data_end))
  {
    struct udphdr *udph = (struct udphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = UDP;
    __builtin_memcpy(&p.src_port, &(udph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(udph -> dest), sizeof(__be16));
  }
  else
  {
    return XDPACTION;
  }

  u64 now = bpf_ktime_get_ns();
  flow_accms accms = {now, 0, 0, 0};
  flow_accms *flow_ptr = flows0.lookup_or_try_init(&p, &accms);

  if (flow_ptr)
  {
    // Update / insert the flow
    flow_ptr->packets += 1;
    flow_ptr->bytes += bytes;
    flow_ptr->end = now + 1;
  }
  else
  {
    // FIXME: should maybe do a perf push to userspace to indicate
    // that map is likely full and should swap
    return XDPACTION;
  }
  return XDPACTION; 
}

// (IPv4 i.e. parse_layer3.call(ctx, 4)) Passed context via program array
int parse_ipv4_flows1(struct xdp_md *ctx) 
{
  // Packet to store in hash
  flow_attrs p = {0, 0, 0, 0, 0, 0};

  // Offset for memory boundary checks
  int offset = sizeof(struct ethhdr);

  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Make sure the data is accessible (see note 2 above)
  if (data + offset + sizeof(struct iphdr) > data_end) 
  {
    return XDP_DROP;
  }

  // Fix IP Header pointer to correct location
  struct iphdr *iph = (struct iphdr *)(data + offset);
  offset += sizeof(struct iphdr);

  // # of bytes for accumulator variables
  uint16_t bytes = (ctx -> data_end) - (ctx -> data);

  // Store L2 + L3 Protocol, src_ip, dst_ip, and #bytes
  p.l2_proto = ETH_P_IP;
  __builtin_memcpy(&p.src_ip, &(iph -> saddr), sizeof(__be32));
  __builtin_memcpy(&p.dst_ip, &(iph -> daddr), sizeof(__be32));

  // Get L4 protocol
  u_short proto = iph -> protocol;

  // Put layer 4 attributes in flow_attrs
  if (proto == ICMP && (data + offset + sizeof(struct icmphdr) < data_end))
  {
    struct icmphdr *icmph = (struct icmphdr *)(data + offset);

    // Store L4 Protocol, src_port (type), and dst_port (code)
    p.l4_proto = ICMP;
    
    __builtin_memcpy(&p.src_port, &(icmph -> type), sizeof(uint8_t));
    __builtin_memcpy(&p.dst_port, &(icmph -> code), sizeof(uint8_t));
  }
  else if (proto == TCP && (data + offset + sizeof(struct tcphdr) < data_end))
  {
    struct tcphdr *tcph = (struct tcphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = TCP;

    __builtin_memcpy(&p.src_port, &(tcph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(tcph -> dest), sizeof(__be16));
  }
  else if (proto == UDP && (data + offset + sizeof(struct udphdr) < data_end))
  {
    struct udphdr *udph = (struct udphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = UDP;
    __builtin_memcpy(&p.src_port, &(udph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(udph -> dest), sizeof(__be16));
  }
  else
  {
    return XDPACTION;
  }

  u64 now = bpf_ktime_get_ns();
  flow_accms accms = {now, 0, 0, 0};
  flow_accms *flow_ptr = flows1.lookup_or_try_init(&p, &accms);

  if (flow_ptr)
  {
    // Update / insert the flow
    flow_ptr->packets += 1;
    flow_ptr->bytes += bytes;
    flow_ptr->end = now + 1;
  }
  else
  {
    // FIXME: should maybe do a perf push to userspace to indicate
    // that map is likely full and should swap
    return XDPACTION;
  }
  return XDPACTION; 
}

// (IPv6 i.e. parse_layer3.call(ctx, 6)) Passed context via program array
int parse_ipv6_flows0(struct xdp_md *ctx)
{
  // Packet to store in hash
  flow_attrs p = {0, 0, 0, 0, 0, 0};

  // Offset for memory boundary checks
  int offset = sizeof(struct ethhdr);

  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Make sure the data is accessible (see note 2 above)
  if (data + offset + sizeof(struct ipv6hdr) > data_end)
  {
    return XDP_DROP;
  }

  // Fix IP Header pointer to correct location
  struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + offset);
  offset += sizeof(struct ipv6hdr);

  // # of bytes for accumulator variables
  uint16_t bytes = (ctx -> data_end) - (ctx -> data);

  // Store L2 + L3 Protocol, src_ip, and dst_ip
  p.l2_proto = ETH_P_IPV6;
  __builtin_memcpy(&p.src_ip, &(ip6h -> saddr), sizeof(__be32));
  __builtin_memcpy(&p.dst_ip, &(ip6h -> daddr), sizeof(__be32));

  // Get L4 Protocol
  u_short proto = ip6h -> nexthdr;

  // Put layer 4 attributes in flow_attrs
  if (proto == ICMP && (data + offset + sizeof(struct icmphdr) < data_end))
  {
    struct icmphdr *icmph = (struct icmphdr *)(data + offset);

    // Store L4 Protocol, src_port (type), and dst_port (code)
    p.l4_proto = ICMP;

    __builtin_memcpy(&p.src_port, &(icmph -> type), sizeof(uint8_t));
    __builtin_memcpy(&p.dst_port, &(icmph -> code), sizeof(uint8_t));
  }
  else if (proto == TCP && (data + offset + sizeof(struct tcphdr) < data_end))
  {
    struct tcphdr *tcph = (struct tcphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = TCP;

    __builtin_memcpy(&p.src_port, &(tcph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(tcph -> dest), sizeof(__be16));
  }
  else if (proto == UDP && (data + offset + sizeof(struct udphdr) < data_end))
  {
    struct udphdr *udph = (struct udphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = UDP;

    __builtin_memcpy(&p.src_port, &(udph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(udph -> dest), sizeof(__be16));
  }
  else
  {
    return XDPACTION;
  }

  u64 now = bpf_ktime_get_ns();
  flow_accms accms = {now, 0, 0, 0};
  flow_accms *flow_ptr = flows0.lookup_or_try_init(&p, &accms);

  if (flow_ptr)
  {
    // Update the flow otherwise
    flow_ptr->packets += 1;
    flow_ptr->bytes += bytes;
    flow_ptr->end = now + 1;
  }
  else
  {
    // FIXME: should maybe do a perf push to userspace to indicate
    // that map is likely full and should swap
    return XDPACTION;
  }
  return XDPACTION; 
}

// (IPv6 i.e. parse_layer3.call(ctx, 6)) Passed context via program array
int parse_ipv6_flows1(struct xdp_md *ctx)
{
  // Packet to store in hash
  flow_attrs p = {0, 0, 0, 0, 0, 0};

  // Offset for memory boundary checks
  int offset = sizeof(struct ethhdr);

  // Retrieve data from context
  void *data = (void *)(long)(ctx -> data);
  void *data_end = (void *)(long)(ctx -> data_end);

  // Make sure the data is accessible (see note 2 above)
  if (data + offset + sizeof(struct ipv6hdr) > data_end)
  {
    return XDP_DROP;
  }

  // Fix IP Header pointer to correct location
  struct ipv6hdr *ip6h = (struct ipv6hdr *)(data + offset);
  offset += sizeof(struct ipv6hdr);

  // # of bytes for accumulator variables
  uint16_t bytes = (ctx -> data_end) - (ctx -> data);

  // Store L2 + L3 Protocol, src_ip, and dst_ip
  p.l2_proto = ETH_P_IPV6;
  __builtin_memcpy(&p.src_ip, &(ip6h -> saddr), sizeof(__be32));
  __builtin_memcpy(&p.dst_ip, &(ip6h -> daddr), sizeof(__be32));

  // Get L4 Protocol
  u_short proto = ip6h -> nexthdr;

  // Put layer 4 attributes in flow_attrs
  if (proto == ICMP && (data + offset + sizeof(struct icmphdr) < data_end))
  {
    struct icmphdr *icmph = (struct icmphdr *)(data + offset);

    // Store L4 Protocol, src_port (type), and dst_port (code)
    p.l4_proto = ICMP;

    __builtin_memcpy(&p.src_port, &(icmph -> type), sizeof(uint8_t));
    __builtin_memcpy(&p.dst_port, &(icmph -> code), sizeof(uint8_t));
  }
  else if (proto == TCP && (data + offset + sizeof(struct tcphdr) < data_end))
  {
    struct tcphdr *tcph = (struct tcphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = TCP;

    __builtin_memcpy(&p.src_port, &(tcph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(tcph -> dest), sizeof(__be16));
  }
  else if (proto == UDP && (data + offset + sizeof(struct udphdr) < data_end))
  {
    struct udphdr *udph = (struct udphdr *)(data + offset);

    // Store L4 Protocol, src_port, and dst_port
    p.l4_proto = UDP;

    __builtin_memcpy(&p.src_port, &(udph -> source), sizeof(__be16));
    __builtin_memcpy(&p.dst_port, &(udph -> dest), sizeof(__be16));
  }
  else
  {
    return XDPACTION;
  }

  u64 now = bpf_ktime_get_ns();
  flow_accms accms = {now, 0, 0, 0};
  flow_accms *flow_ptr = flows1.lookup_or_try_init(&p, &accms);

  if (flow_ptr)
  {
    // Update the flow otherwise
    flow_ptr->packets += 1;
    flow_ptr->bytes += bytes;
    flow_ptr->end = now + 1;
  }
  else
  {
    // FIXME: should maybe do a perf push to userspace to indicate
    // that map is likely full and should swap
    return XDPACTION;
  }
  return XDPACTION; 
}
