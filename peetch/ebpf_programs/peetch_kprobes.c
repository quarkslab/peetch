// SPDX-License-Identifier: GPL-2.0+
// Guillaume Valadon <gvaladon@quarkslab.com>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>


#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
#include <linux/sched.h>
#include <net/sock.h>


struct key_t {
  u32 dst;
  u32 src;
  u64 padding;
};

struct data_t {
  u32 pid;
  char name[64];
};

BPF_HASH(pid_cache, struct key_t *);

BPF_PERF_OUTPUT(connect_events);
BPF_PERF_OUTPUT(skb_events);

int process_frame(struct __sk_buff *skb) {
  // Data accessors
  unsigned char *data = (void *)(long)skb->data;
  unsigned char *data_end = (void *)(long)skb->data_end;

  // Mapping data to the Ethernet and IP headers
  struct ethhdr *eth = (struct ethhdr *)data;
  struct iphdr *iph = (struct iphdr*) (data + sizeof(struct ethhdr));

  // Simple length check
  if ((data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > data_end)
    return TC_ACT_OK;

  // Discard everything but IPv4
  if (ntohs(eth->h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  // Discard everything but TCP
  if (iph->protocol != IPPROTO_TCP)
    return TC_ACT_OK;

  // Retrieve the PID and the process name from the IP addresses
  struct key_t key = { .dst = iph->daddr, .src = iph->saddr };
  struct data_t *value = (struct data_t *) pid_cache.lookup((struct key_t **)&key);
  if (value == NULL) {
    key.dst = iph->saddr;
    key.src = iph->daddr;
    value = (struct data_t *) pid_cache.lookup((struct key_t **)&key);
    if (value == NULL)
      return TC_ACT_OK;
  }

  // Check the PID
  if (value->pid == 0)
    return TC_ACT_OK;

  skb_events.perf_submit_skb(skb, skb->len, value, sizeof(value));

  return TC_ACT_OK;
}

int kprobe_security_sk_classify_flow(struct pt_regs *ctx, struct sock *sk, struct flowi *fl) {
  // Discard everything but IPv4
  if (sk->sk_family != AF_INET)
    return 0;

  // Extract IPv4 related structures
  union flowi_uli uli;
  struct flowi4 ip4;
  bpf_probe_read(&ip4, sizeof(ip4), &fl->u.ip4);
  bpf_probe_read(&uli, sizeof(uli), &ip4.uli);

  // Get IP addresses and ports
  struct key_t key;
  struct data_t data;

  bpf_probe_read(&key.src,
                 sizeof(sk->__sk_common.skc_daddr),
                 &sk->__sk_common.skc_daddr);
  bpf_probe_read(&key.dst,
                 sizeof(sk->__sk_common.skc_rcv_saddr),
                 &sk->__sk_common.skc_rcv_saddr);

  // Get and store the PID
  u64 id = bpf_get_current_pid_tgid();
  data.pid = id >> 32;

  // Get and store the process name
  bpf_get_current_comm(data.name, 64);

  // Store data
  pid_cache.update((struct key_t **) &key, (unsigned long long *) &data);

  return 0;
}

int connect_v4_prog(struct bpf_sock_addr *ctx) {
  struct data_t data;

  // Get and store the PID
  u64 id = bpf_get_current_pid_tgid();
  data.pid = id >> 32;

  // Get and store the process name
  bpf_get_current_comm(data.name, 64);

  // Send the event to userland
  connect_events.perf_submit(ctx, &data, sizeof(data));

  /*
  Note:
  - 1: accept
  - 0: discard
  */
  return 1;
}
