// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

struct {
  __uint(type, BPF_MAP_TYPE_SOCKMAP);
  __uint(max_entries, 2);
  __type(key, unsigned int);
  __type(value, unsigned int);
} sock_map SEC(".maps");

SEC("sk_skb/parser") int parser(struct __sk_buff *skb)
{
  bpf_printk("parser\n");
  return skb->len;
}

SEC("sk_skb/verdict") int verdict(struct __sk_buff *skb) {
  bpf_printk("verdict\n");
  return SK_PASS;
}

char __license[] SEC("license") = "GPL";
