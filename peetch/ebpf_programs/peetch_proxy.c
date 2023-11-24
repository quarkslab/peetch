// SPDX-License-Identifier: GPL-2.0+
// Guillaume Valadon <gvaladon@quarkslab.com>

#include <linux/bpf.h>
#include <linux/in.h>

struct data_t {
  u32 pid;
  char name[64];
  u32 ip;
  u32 port;
};

BPF_HASH(pid_cache, u64);

BPF_HASH(destination_cache, u16, struct data_t);

int connect_v4_prog(struct bpf_sock_addr *ctx) {
  struct data_t data;

  // Get and store the PID
  u64 id = bpf_get_current_pid_tgid();
  data.pid = id >> 32;

  // Do not intercept connection from peetch itself
  if (PEETCH_PROXY_PID == data.pid)
    return 1;

  // Do not intercept well known TCP services
  if (ctx->user_port == bpf_htons(53)) // DNS
    return 1;

  // Check if the PID is in the cache
  u64 *tmp_id = pid_cache.lookup((u64*) &id);
  if (tmp_id == NULL)
    return 1;
  if (*tmp_id != id)
    return 1;

  // Get and store the process name
  bpf_get_current_comm(data.name, 64);

  // Rewrite the source port
  struct sockaddr_in sa = {};
	sa.sin_family = AF_INET;
  u16 new_port = bpf_htons(data.pid & 0xFFFF); // lower part of the PID will be used as the TCP source port
  sa.sin_port = new_port;
  sa.sin_addr.s_addr = bpf_htonl(0x7f000001); // 127.0.0.1

	if (bpf_bind(ctx, (struct sockaddr *) &sa, sizeof(sa)) != 0)
		return 0;

  // Get and store the real destination IPv4 address and port
  data.ip = ctx->user_ip4;
  data.port = ctx->user_port;

  // Store the connection data into the cache
  destination_cache.update(&new_port, &data);

  // Divert the connection to peetch proxy
  ctx->user_ip4 = 0x0100007f;
	ctx->user_port = bpf_htons(2807);

  /*
  Note:
  - 1: accept
  - 0: discard
  */
  return 1;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
  #define _PATH_MAX 128
  char filename[_PATH_MAX + 1];

  // Retrieve the filename
  long ret = bpf_probe_read((void*)&filename, _PATH_MAX, (void*)args->filename);
   if (ret != 0) {
     //bpf_trace_printk("sys_enter_openat() - bpf_probe_read() failed\n");
     return 0;
   }

  // Check if the filename contains "libssl.so"
  for (u16 i=8; i < _PATH_MAX; i++) {
    if (filename[i-8] == 'l' && filename[i-7] == 'i'  && filename[i-6] == 'b' && filename[i-5] == 's' &&
        filename[i-4] == 's' && filename[i-3] == 'l'  && filename[i-2] == '.' && filename[i-1] == 's') {

      // Get and store the PID
      u64 id = bpf_get_current_pid_tgid();
      u64 pid = id >> 32;
      pid_cache.update(&id, &id);
      break;
    }
  }

  return 0;
}
