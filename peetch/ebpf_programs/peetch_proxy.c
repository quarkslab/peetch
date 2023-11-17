// SPDX-License-Identifier: GPL-2.0+
// Guillaume Valadon <gvaladon@quarkslab.com>

struct data_t {
  u32 pid;
  char name[64];
};

BPF_PERF_OUTPUT(connect_events);

BPF_HASH(pid_cache, u64);

int connect_v4_prog(struct bpf_sock_addr *ctx) {
  struct data_t data;

  // Get and store the PID
  u64 id = bpf_get_current_pid_tgid();
  data.pid = id >> 32;

  // Check if the PID is in the cache
  u64 *tmp_id = pid_cache.lookup((u64*) &id);
  if (tmp_id == NULL)
    return 1;
  if (*tmp_id != id)
    return 1;
  pid_cache.delete((u64*) &id);

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
