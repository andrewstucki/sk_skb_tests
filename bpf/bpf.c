// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define AF_INET 2
#define AF_INET6 10

#define ip_dump(ip) ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(max_entries, 2);
  __type(key, unsigned int);
  __type(value, unsigned int);
} sock_map SEC(".maps");

SEC("sk_skb/parser")
int parser(struct __sk_buff *skb)
{
  if (skb->family == AF_INET)
  {
    bpf_printk("parser ipv4: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", ip_dump(skb->remote_ip4), bpf_ntohl(skb->remote_port), ip_dump(skb->local_ip4), skb->local_port);
  }

  return skb->len;
}

SEC("sk_skb/verdict")
int verdict(struct __sk_buff * skb)
{
  if (skb->family == AF_INET)
  {
    bpf_printk("verdict ipv4: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", ip_dump(skb->remote_ip4), bpf_ntohl(skb->remote_port), ip_dump(skb->local_ip4), skb->local_port);
  }

  return SK_PASS;
}

char __license[] SEC("license") = "GPL";
