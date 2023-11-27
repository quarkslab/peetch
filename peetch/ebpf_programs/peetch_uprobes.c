// SPDX-License-Identifier: GPL-2.0+
// Guillaume Valadon <gvaladon@quarkslab.com>

#include <linux/in.h>
#include <linux/ptrace.h>


// Data structure sent to userland
struct tls_event_t {
    u32 addr;
    u16 port;
    u16 tls_version;
    #define COMM_MAX_LEN 64
    char comm[COMM_MAX_LEN];
    #define MESSAGE_MAX_LEN 64
    u8 message[MESSAGE_MAX_LEN];
    u32 message_length;
    u32 pid;
    u32 is_read;
};
BPF_PERF_OUTPUT(tls_events);


// Store SSL_* buffer information
struct SSL_buffer_t {
    u64 ptr;
    u32 length;
    u32 tls_version;
    u32 is_read;
};
BPF_HASH(SSL_read_buffers, u32, struct SSL_buffer_t);


// Store connect information indexed by PID
BPF_HASH(pid_cache, u32);


// TLS information
struct TLS_information_t {
    u16 tls_version;
    #define CIPHERSUITE_MAX_LEN 32
    char ciphersuite[CIPHERSUITE_MAX_LEN];
    #define MASTER_SECRET_MAX_LEN 48
    u8 master_secret[MASTER_SECRET_MAX_LEN];
    #define CLIENT_RANDOM_MAX_LEN 32
    u8 client_random[CLIENT_RANDOM_MAX_LEN];
};
BPF_HASH(tls_information_cache, u32, struct TLS_information_t);


TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    // Retrieve the sockaddr_in structure
    struct sockaddr_in addr_in;
    long ret = bpf_probe_read((void*)&addr_in, sizeof(addr_in), args->uservaddr);
    if (ret != 0) {
        bpf_trace_printk("sys_enter_connect() - bpf_probe_read() failed\n");
        return 0;
    }

    // Discard everything but IPv4
    if (addr_in.sin_family != AF_INET)
        return 0;

    // Retrieve the PID
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Store a TLS event in the pid_cache
    struct tls_event_t event = { .port = addr_in.sin_port,
                                 .addr = addr_in.sin_addr.s_addr};
    pid_cache.update(&pid, (u64*)&event);

    return 0;
}


// Dummy openssl ssl_st structure
struct ssl_st {
    int version;
};


static u16 get_tls_version(void *ssl_st_ptr) {
    // Extract the TLS version from a struct ssl_str pointer
    struct ssl_st ssl;

    long ret = bpf_probe_read(&ssl, sizeof(ssl), ssl_st_ptr);
    if (ret != 0) {
        bpf_trace_printk("get_tls_version() - bpf_probe_read() failed\n");
        return -1;
    }

    return ssl.version;
}


static void parse_session(struct pt_regs *ctx, u16 tls_version) {
    // Parse a struct sl_session_st pointer and send
    // data to userspace

    // TLS information sent to userspace
    struct TLS_information_t tls_information;
    __builtin_memset(&tls_information, 0, sizeof(tls_information)); // it makes the eBPF verifier happy!
    tls_information.tls_version = tls_version;

    // Get a ssl_st pointer
    void *ssl_st_ptr = (void *) PT_REGS_PARM1(ctx);

    // Get a ssl_session_st pointer
    u64 *ssl_session_st_ptr = (u64 *) (ssl_st_ptr + SSL_SESSION_OFFSET);

    u64 address;
    long ret = bpf_probe_read(&address, sizeof(address), ssl_session_st_ptr);
    if (ret != 0)
        bpf_trace_printk("parse_session() #1 - bpf_probe_read() failed\n");

    // Access the TLS 1.2 master secret
    void *ms_ptr = (void *) (address + MASTER_SECRET_OFFSET);
    ret = bpf_probe_read(&tls_information.master_secret,
                              sizeof(tls_information.master_secret), ms_ptr);
    if (ret != 0)
        bpf_trace_printk("parse_session() #2 - bpf_probe_read() failed\n");

    // Get a ssl_cipher_st pointer
    void *ssl_cipher_st_ptr = (void *) (address + SSL_CIPHER_OFFSET);
    ret = bpf_probe_read(&address, sizeof(address), ssl_cipher_st_ptr);
    if (ret != 0)
        bpf_trace_printk("parse_session() #3 - bpf_probe_read() failed\n");

    // Get the SSL_cipher_st point to the name member
    ssl_cipher_st_ptr = (void *) (address + 8);
    ret = bpf_probe_read(&address, sizeof(address), ssl_cipher_st_ptr);
    if (ret != 0)
        bpf_trace_printk("parse_session() #4 - bpf_probe_read() failed\n");

    // Access the TLS ciphersuite
    void *cs_ptr = (void *) address;
    ret = bpf_probe_read(&tls_information.ciphersuite,
                              sizeof(tls_information.ciphersuite), cs_ptr);
    if (ret != 0)
        bpf_trace_printk("parse_session() #5 - bpf_probe_read() failed\n");

    // Retrieve the Client Random
    void* client_hello_ptr = (void *) (ssl_st_ptr + CLIENT_HELLO_OFFSET);
    ret = bpf_probe_read(&address, sizeof(address), client_hello_ptr);
    if (ret != 0)
        bpf_trace_printk("parse_session() #6 - bpf_probe_read() failed\n");

    u8 client_random[CLIENT_RANDOM_MAX_LEN + CLIENT_RANDOM_OFFSET];
    ret = bpf_probe_read(client_random, sizeof(client_random), client_hello_ptr);
    if (ret != 0)
        bpf_trace_printk("parse_session() #7 - bpf_probe_read() failed\n");

    ret = bpf_probe_read(&tls_information.client_random, sizeof(tls_information.client_random), client_random + CLIENT_RANDOM_OFFSET);
    if (ret != 0)
        bpf_trace_printk("parse_session() #8 - bpf_probe_read() failed\n");

    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    tls_information_cache.update(&pid, &tls_information);
}


static int SSL_read_write(struct pt_regs *ctx, u16 tls_version, struct SSL_buffer_t *buffer) {
    // A buffer is needed
    if (buffer == NULL)
        return 0;

    // Retrieve connect() information for PID
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct tls_event_t *event = (struct tls_event_t*) pid_cache.lookup(&pid);
    if (event == NULL) {
    
    	//get ppid to check if it is a child of a known process 
    	struct task_struct *task;
		task = (struct task_struct *)bpf_get_current_task();
		pid = task->real_parent->tgid;
		
		event = (struct tls_event_t*) pid_cache.lookup(&pid);
    	if(event == NULL)
    		return 0;
    }

    // Build a new TLS event and fill it
    struct tls_event_t new_event;

    bpf_get_current_comm(&new_event.comm, COMM_MAX_LEN);
    new_event.pid = pid;
    new_event.port = event->port;
    new_event.addr = event->addr;
    new_event.is_read = buffer->is_read;
    new_event.tls_version = tls_version;

    long ret = bpf_probe_read(&new_event.message,
                             sizeof(new_event.message), (void*) buffer->ptr);
    if (ret != 0) {
        bpf_trace_printk("SSL_read_write() - bpf_probe_read() failed\n");
        return 0;
    }
    new_event.message_length = buffer->length;

    // Send the event to userland
    tls_events.perf_submit(ctx, &new_event, sizeof(new_event));

    // Flush the PID cache
    if (DIRECTIONS)  // this will be replaced by a boolean in Python
        pid_cache.delete(&pid);

    return 0;
}


int SSL_read(struct pt_regs *ctx) {
    // Retrieve the PID
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Store a SSL read buffer information in the cache
    struct SSL_buffer_t buffer;
    __builtin_memset(&buffer, 0, sizeof(buffer));
    buffer.ptr = PT_REGS_PARM2(ctx);

    // Get TLS version
    void *ssl_st_ptr = (void *) PT_REGS_PARM1(ctx);
    buffer.tls_version = get_tls_version(ssl_st_ptr);

    SSL_read_buffers.update(&pid, &buffer);

    return 0;
}


int SSL_read_ret(struct pt_regs *ctx) {
    // Discard if nothing was received
    int buffer_length = PT_REGS_RC(ctx);
    if (buffer_length == -1)
        return 0;

    // Retrieve SSL read buffers information for PID
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    struct SSL_buffer_t *buffer = (struct SSL_buffer_t*) SSL_read_buffers.lookup(&pid);
    if (buffer == NULL)
        return 0;

    // Add buffer information
    buffer->length = buffer_length;
    buffer->is_read = 1;

    long ret = SSL_read_write(ctx, buffer->tls_version, buffer);
    SSL_read_buffers.delete(&pid);

    return ret;
}


int SSL_write(struct pt_regs *ctx) {
    // Retrieve the buffer information
    struct SSL_buffer_t buffer;

    buffer.ptr = PT_REGS_PARM2(ctx);
    buffer.length = PT_REGS_PARM3(ctx);
    buffer.is_read = 0;

    // Get TLS version
    void *ssl_st_ptr = (void *) PT_REGS_PARM1(ctx);
    u16 tls_version = get_tls_version(ssl_st_ptr);

    parse_session(ctx, tls_version);

    return SSL_read_write(ctx, tls_version, &buffer);
}
