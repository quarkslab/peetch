# SPDX-License-Identifier: GPL-2.0+
# Guillaume Valadon <gvaladon@quarkslab.com>

import argparse
import asyncio
import atexit
import ctypes as ct
import binascii
import os
import peetch.utils
import socket
import struct
import sys
import time

from bcc import BPF, BPFProgType, BPFAttachType
import pyroute2
from scapy.all import Ether, wrpcapng, hexdump


global BPF_HANDLER, BPF_TLS_HANDLER

EBPF_PROGRAMS_DIRNAME = os.path.join(os.path.dirname(__file__),
                                     "ebpf_programs/")
BPF_DUMP_PROGRAM_FILENAME = "%s/peetch_kprobes.c" % EBPF_PROGRAMS_DIRNAME
BPF_DUMP_PROGRAM_SOURCE = open(BPF_DUMP_PROGRAM_FILENAME).read()
BPF_TLS_PROGRAM_FILENAME = "%s/peetch_uprobes.c" % EBPF_PROGRAMS_DIRNAME
BPF_TLS_PROGRAM_SOURCE = open(BPF_TLS_PROGRAM_FILENAME).read()
BPF_PROXY_PROGRAM_FILENAME = "%s/peetch_proxy.c" % EBPF_PROGRAMS_DIRNAME
BPF_PROXY_PROGRAM_SOURCE = open(BPF_PROXY_PROGRAM_FILENAME).read()
PACKETS_CAPTURED = []


def load_classifier(interface, ebpf_function):
    """
    Load an eBPF TC Classifier
    """
    iproute_handler = pyroute2.IPRoute()

    ip_link = iproute_handler.link_lookup(ifname=interface)
    if not ip_link:
        sys.exit()

    ip_link = ip_link[0]
    iproute_handler.tc("add", "clsact", ip_link)

    # add ingress clsact
    iproute_handler.tc("add-filter", "bpf", ip_link, ":1",
                       fd=ebpf_function.fd, name=ebpf_function.name,
                       parent="ffff:fff2")

    # add egress clsact
    iproute_handler.tc("add-filter", "bpf", ip_link, ":1",
                       fd=ebpf_function.fd, name=ebpf_function.name,
                       parent="ffff:fff3")


def unload_classifier(interface):
    """
    Unload an eBPF TC Classifier
    """
    os.system("tc qdisc del dev %s clsact" % args.interface)


def exit_handler_command(interface, filename, bpf_handler):
    """
    Exit command nicely
    """
    time.sleep(0.01)
    bpf_handler.detach_kprobe(event="security_sk_classify_flow",
                              fn_name="kprobe_security_sk_classify_flow")
    unload_classifier(interface)
    if filename:
        wrpcapng(filename, PACKETS_CAPTURED)


def exit_handler_proxy(bpf_handler, connect_function, cgroup_fd):
    """
    Exit proxy nicely
    """
    time.sleep(0.01)
    bpf_handler.detach_func(connect_function, cgroup_fd,
                            BPFAttachType.CGROUP_INET4_CONNECT)
    if cgroup_fd > 0:
        os.close(cgroup_fd)


def handle_skb_event(cpu, data, size):
    """
    Handle SKB events from the kernel
    """

    # Structure retrieved from the kernel
    class SkbEvent(ct.Structure):
        _fields_ = [("pid", ct.c_uint32),
                    ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32)))]

    # Map the data from kernel to the structure
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    data = bytes(skb_event.raw)

    # Extract the process name
    for i in range(len(data)):
        if data[i] == 0:
            break
    process_name = data[:i].decode("utf-8", "replace")
    data = data[i:]

    process_information = "%s/%d" % (process_name, skb_event.pid)

    # Parse the packet with Scapy
    pkt = Ether(data)

    if args.write:
        pkt.comment = str(process_information)
        PACKETS_CAPTURED.append(pkt)
    else:
        if not args.raw:
            print(process_information, end=" - ")
        print(pkt.summary())


def dump_command(args):
    # Compile eBPF programs
    bpf_handler = BPF(text=BPF_DUMP_PROGRAM_SOURCE)

    # Attach the kprobe
    bpf_handler.attach_kprobe(event="security_sk_classify_flow",
                              fn_name="kprobe_security_sk_classify_flow")

    # Setup the exit handler
    atexit.register(exit_handler_command, args.interface, args.write,
                    bpf_handler)

    # Load eBPF TC Classifier
    classifier_function = bpf_handler.load_func("process_frame", BPF.SCHED_CLS)
    load_classifier(args.interface, classifier_function)

    # Handle incoming skb events
    bpf_handler["skb_events"].open_perf_buffer(handle_skb_event)
    try:
        while True:
            bpf_handler.perf_buffer_poll()
    except KeyboardInterrupt:
        pass


def handle_tls_event(cpu, data, size):
    class TLSEvent(ct.Structure):
        _fields_ = [("address", ct.c_uint32),
                    ("port", ct.c_uint16),
                    ("tls_version", ct.c_uint16),
                    ("comm", ct.c_char * 64),
                    ("message", ct.c_uint8 * 64),
                    ("message_length", ct.c_uint32),
                    ("pid", ct.c_uint32),
                    ("is_read", ct.c_uint32)]

    # Map the data from kernel to the structure
    tls_event = ct.cast(data, ct.POINTER(TLSEvent)).contents

    # Get TLS information
    pid_to_delete = None
    master_secret = None
    ciphersuite = None
    bpf_map_tls_information = BPF_TLS_HANDLER["tls_information_cache"]
    for pid, tls_info in bpf_map_tls_information.items_lookup_batch():
        if pid.value == tls_event.pid:
            ciphersuite = tls_info.ciphersuite.decode("ascii", "ignore")
            master_secret = binascii.hexlify(tls_info.master_secret)
            master_secret = master_secret.decode("ascii", "ignore")
            pid_to_delete = [pid]
            break

    # Delete pid from the eBPF map
    if not pid_to_delete:
        bpf_map_tls_information.items_delete_batch(pid_to_delete)

    # Unpack the IPv4 destination address
    addr = struct.pack("I", tls_event.address)

    # Discard empty content
    if args.content and tls_event.message_length == 0:
        return

    # Display the TLS event
    if args.directions:
        if tls_event.is_read:
            print("->", end=" ")
        else:
            print("<-", end=" ")
    print("%s (%d)" % (tls_event.comm.decode("ascii", "replace"),
                       tls_event.pid), end=" ")
    print("%s/%d" % (socket.inet_ntop(socket.AF_INET, addr),
                     socket.ntohs(tls_event.port)), end=" ")

    version = (tls_event.tls_version & 0xF) - 1
    print("TLS1.%d %s" % (version, ciphersuite))

    # Display TLS secrets
    if (args.secrets or args.write) and tls_event.tls_version == 0x303:
        key_log = "CLIENT_RANDOM 28071980 %s\n" % master_secret
        if args.secrets:
            print("\n   %s\n" % key_log)
        if args.write:
            fd = open("%d-master_secret.log" % pid.value, "w")
            fd.write(key_log)
            fd.close()

    # Display the message content in hexadecimal
    if args.content and tls_event.message_length:
        hex_message = hexdump(tls_event.message[:tls_event.message_length],
                              dump=True)
        print("\n   ", end="")
        print(hex_message.replace("\n", "\n   "))
        print()


def _tls_ebpf_programs(directions_bool, args_ssl_session_offset,
                       args_ssl_cipher_offset, args_master_secret_offset):
    # Get SSL structures offsets
    offsets = [str(offset) for offset in peetch.utils.get_offsets()]
    ssl_session_offset, ssl_cipher_offset, master_secret_offset, \
        client_hello_offset, client_random_offset = offsets

    if ssl_session_offset == ssl_cipher_offset and \
       ssl_cipher_offset == master_secret_offset and master_secret_offset == '0':  # noqa: E501
        return None

    if args_ssl_session_offset is not None:
        ssl_session_offset = str(args_ssl_session_offset)

    if args_ssl_cipher_offset is not None:
        ssl_cipher_offset = str(args_ssl_cipher_offset)

    if args_master_secret_offset is not None:
        master_secret_offset = str(args_master_secret_offset)

    if args.client_hello_offset is not None:
        client_hello_offset = str(args.client_hello_offset)

    if args.client_random_offset is not None:
        client_random_offset = str(args.client_random_offset)

    # Compile eBPF programs
    ebpf_programs = BPF_TLS_PROGRAM_SOURCE.replace("DIRECTIONS",
                                                   directions_bool)
    ebpf_programs = ebpf_programs.replace("SSL_SESSION_OFFSET",
                                          ssl_session_offset)
    ebpf_programs = ebpf_programs.replace("MASTER_SECRET_OFFSET",
                                          master_secret_offset)
    ebpf_programs = ebpf_programs.replace("SSL_CIPHER_OFFSET",
                                          ssl_cipher_offset)
    ebpf_programs = ebpf_programs.replace("CLIENT_HELLO_OFFSET",
                                          client_hello_offset)
    ebpf_programs = ebpf_programs.replace("CLIENT_RANDOM_OFFSET",
                                          client_random_offset)

    return ebpf_programs


def tls_command(args):
    global BPF_TLS_HANDLER

    # Process arguments
    if args.content:
        args.directions = True

    directions_bool = "1"
    if args.directions:
        directions_bool = "0"

    ebpf_programs = _tls_ebpf_programs(directions_bool,
                                       args.ssl_session_offset,
                                       args.ssl_cipher_offset,
                                       args.master_secret_offset)
    if ebpf_programs is None:
        print("ERROR: cannot guess SSL offsets!", file=sys.stderr)
        sys.exit(1)
    bpf_handler = BPF(text=ebpf_programs)
    BPF_TLS_HANDLER = bpf_handler

    # Attach the probes
    try:
        bpf_handler.attach_uprobe(name="ssl",
                                  sym="SSL_write", fn_name="SSL_write")
        bpf_handler.attach_uprobe(name="ssl",
                                  sym="SSL_read", fn_name="SSL_read")
        bpf_handler.attach_uretprobe(name="ssl",
                                     sym="SSL_read", fn_name="SSL_read_ret")
    except Exception:
        print("tls - cannot attach to eBPF probes!")
        sys.exit()


    def handle_tls_event(cpu, data, size):
        class TLSEvent(ct.Structure):
            _fields_ = [("address", ct.c_uint32),
                        ("port", ct.c_uint16),
                        ("tls_version", ct.c_uint16),
                        ("comm", ct.c_char * 64),
                        ("message", ct.c_uint8 * 64),
                        ("message_length", ct.c_uint32),
                        ("pid", ct.c_uint32),
                        ("is_read", ct.c_uint32)]

        # Map the data from kernel to the structure
        tls_event = ct.cast(data, ct.POINTER(TLSEvent)).contents

        # Get TLS information
        pid_to_delete = None
        master_secret = None
        ciphersuite = None
        client_random = None
        bpf_map_tls_information = bpf_handler["tls_information_cache"]
        for pid, tls_info in bpf_map_tls_information.items_lookup_batch():
            if pid.value == tls_event.pid:
                ciphersuite = tls_info.ciphersuite.decode("ascii", "ignore")
                master_secret = binascii.hexlify(tls_info.master_secret)
                master_secret = master_secret.decode("ascii", "ignore")
                client_random = binascii.hexlify(tls_info.client_random)
                client_random = client_random.decode("ascii", "ignore")
                pid_to_delete = [pid]
                break

        # Delete pid from the eBPF map
        if not pid_to_delete:
            bpf_map_tls_information.items_delete_batch(pid_to_delete)

        # Unpack the IPv4 destination address
        addr = struct.pack("I", tls_event.address)

        # Discard empty content
        if args.content and tls_event.message_length == 0:
            return

        # Display the TLS event
        if args.directions:
            if tls_event.is_read:
                print("->", end=" ")
            else:
                print("<-", end=" ")
        print("%s (%d)" % (tls_event.comm.decode("ascii", "replace"),
                           tls_event.pid), end=" ")
        print("%s/%d" % (socket.inet_ntop(socket.AF_INET, addr),
                         socket.ntohs(tls_event.port)), end=" ")

        version = (tls_event.tls_version & 0xF) - 1
        print("TLS1.%d %s" % (version, ciphersuite))

        # Display TLS secrets
        if (args.secrets or args.write) and tls_event.tls_version == 0x303:
            key_log = "CLIENT_RANDOM %s %s\n" % (client_random, master_secret)
            if args.secrets:
                print("\n   %s\n" % key_log)
            if args.write:
                fd = open("%d-master_secret.log" % pid.value, "w")
                fd.write(key_log)
                fd.close()

        # Display the message content in hexadecimal
        if args.content and tls_event.message_length:
            hex_message = hexdump(tls_event.message[:tls_event.message_length],
                                  dump=True)
            print("\n   ", end="")
            print(hex_message.replace("\n", "\n   "))
            print()

    bpf_handler["tls_events"].open_perf_buffer(handle_tls_event)
    while True:
        try:
            bpf_handler.perf_buffer_poll()
        except KeyboardInterrupt:
            sys.exit()


def handle_connect_event(cpu, data, size):
    """
    Handle connect events from the kernel
    """

    # Structures retrieved from the kernel
    class DataEvent(ct.Structure):
        _fields_ = [("pid", ct.c_uint32),
                    ("name", ct.c_char * 64),
                    ("address", ct.c_uint32),
                    ("port", ct.c_uint32)]

    # Map the data from kernel to the structure
    data_event = ct.cast(data, ct.POINTER(DataEvent)).contents
    pid = data_event.pid
    process_name = data_event.name.decode("ascii", "replace")

    # Retrieve destination IP and port
    address_packed = struct.pack("I", data_event.address)
    address = socket.inet_ntop(socket.AF_INET, address_packed)
    port = socket.ntohs(data_event.port)
    print(f"\r{process_name}/{pid} -> {address}/{port}")

    # Get TLS information
    # Note: sleeping could likely be avoided by grabbing the TLS information from
    #       a perf buffer, then accessing DataEvent
    time.sleep(0.2)
    pid_to_delete = None
    master_secret = None
    ciphersuite = None
    bpf_map_tls_information = BPF_TLS_HANDLER["tls_information_cache"]
    for tls_pid, tls_info in bpf_map_tls_information.items_lookup_batch():
        if tls_pid.value == pid:
            ciphersuite = tls_info.ciphersuite.decode("ascii", "ignore")
            master_secret = binascii.hexlify(tls_info.master_secret)
            master_secret = master_secret.decode("ascii", "ignore")
            pid_to_delete = [pid]
            break
    if ciphersuite and len(ciphersuite):
        print("  ", master_secret, ciphersuite)

    # Delete pid from the eBPF map
    if not pid_to_delete:
        bpf_map_tls_information.items_delete_batch(pid_to_delete)


def proxy_command(args):
    global BPF_HANDLER, BPF_TLS_HANDLER

    # Compile eBPF programs
    ebpf_programs = BPF_PROXY_PROGRAM_SOURCE.replace("PEETCH_PROXY_PID",
                                                     str(os.getpid()))
    bpf_handler = BPF(text=ebpf_programs)
    BPF_HANDLER = bpf_handler

    # Load the eBPF function
    connect_function = bpf_handler.load_func("connect_v4_prog",
                                             prog_type=BPFProgType.CGROUP_SOCK_ADDR,  # noqa: E501
                                             attach_type=BPFAttachType.CGROUP_INET4_CONNECT)  # noqa: E501

    # Attach the eBPF function to the default cgroup
    cgroup_fd = os.open("/sys/fs/cgroup", os.O_RDONLY)
    bpf_handler.attach_func(connect_function, cgroup_fd,
                            BPFAttachType.CGROUP_INET4_CONNECT)

    # Get SSL structures offsets
    offsets = [str(offset) for offset in peetch.utils.get_offsets()]
    ssl_session_offset, ssl_cipher_offset, master_secret_offset = offsets

    # Attach the SSL_* uprobes
    ebpf_programs = _tls_ebpf_programs("1", None, None, None)
    if ebpf_programs is None:
        print("ERROR: cannot guess SSL offsets!", file=sys.stderr)
        sys.exit(1)
    bpf_tls_handler = BPF(text=ebpf_programs)
    BPF_TLS_HANDLER = bpf_tls_handler
    try:
        bpf_tls_handler.attach_uprobe(name="ssl",
                                      sym="SSL_write", fn_name="SSL_write")
        bpf_tls_handler.attach_uprobe(name="ssl",
                                      sym="SSL_read", fn_name="SSL_read")
        bpf_tls_handler.attach_uretprobe(name="ssl",
                                         sym="SSL_read", fn_name="SSL_read_ret")  # noqa: E501
    except Exception:
        print("proxy - cannot attach to eBPF SSL_* uprobes!")
        sys.exit()

    print("[!] Intercepting calls to connect()")

    # Setup the exit handler
    atexit.register(exit_handler_proxy, bpf_handler,
                    connect_function, cgroup_fd)

    bpf_handler["connect_events"].open_perf_buffer(handle_connect_event)

    async def poll_perf():
        """
        async perf buffer polling
        """
        def tmp_poll_perf():
            while True:
                try:
                    bpf_handler.perf_buffer_poll(timeout=100)
                except KeyboardInterrupt:
                    sys.exit()
        await asyncio.to_thread(tmp_poll_perf)

    async def dots():
        """
        async dummy processing
        """
        while True:
            await asyncio.sleep(0.5)
            print(".", end="", flush=True)

    async def pipe(reader, writer, direction):
        """"
        From https://stackoverflow.com/a/46422554
        """
        try:
            while not reader.at_eof():
                data = await reader.read(2048)
                #print("data", direction, data)
                writer.write(data)
        finally:
            writer.close()

    async def handle_client(local_reader, local_writer):
        ip_src, port_src = local_reader._transport.get_extra_info('peername')
        print("---", ip_src, port_src)

        bpf_map_destination_cache = BPF_HANDLER["destination_cache"]

        real_address = None
        real_port = None
        destination_key_to_delete = None

        for destination_key, destination_value in bpf_map_destination_cache.items_lookup_batch():
            real_address = socket.inet_ntop(socket.AF_INET, struct.pack("I", destination_value.value >> 32))
            real_port = socket.ntohs(destination_value.value & 0xFFFFFFFF)
            print(socket.ntohs(destination_key.value), real_address, real_port)
            if socket.ntohs(destination_key.value) == port_src:
                destination_key_to_delete = [destination_key]
                break

        # TODO: clean the cache
        #print("DBG")
        #if destination_key_to_delete is not None:
        #    bpf_map_destination_cache.items_delete_batch(destination_key_to_delete)
        #else:
        #    print("!!! Did not find the real destination")
        #    local_writer.close()
        #    return
        #print("dbg")

        try:
            remote_reader, remote_writer = await asyncio.open_connection(real_address, real_port)
            pipe1 = pipe(local_reader, remote_writer, "->")
            pipe2 = pipe(remote_reader, local_writer, "<-")
            await asyncio.gather(pipe1, pipe2)
        finally:
            local_writer.close()

    async def tcp_proxy():
        """
        async TCP proxy
        """
        server = await asyncio.start_server(handle_client, "127.0.0.1", 2807)
        await server.serve_forever()

    async def all_tasks():
        await asyncio.gather(tcp_proxy(), dots(), poll_perf())

    asyncio.run(all_tasks())


def main():
    global args
    argv = sys.argv[1:]

    # Parsing arguments
    parser = argparse.ArgumentParser(description="peetch - an eBPF playground")
    subparser = parser.add_subparsers()
    parser.set_defaults(func=lambda args: parser.print_help())

    # Prepare the 'dump' subcommand
    dump_parser = subparser.add_parser("dump",
                                       help="Sniff packets with eBPF")
    dump_parser.add_argument("--raw", action="store_true",
                             help="display packets only")
    dump_parser.add_argument("--write", type=str,
                             help="pcapng filename")
    dump_parser.add_argument("--interface", type=str,
                             help="interface name", default="eth0")
    dump_parser.set_defaults(func=dump_command)

    # Prepare the 'identify' subcommand
    dump_parser = subparser.add_parser("tls",
                                       help="Identify processes that uses TLS")
    dump_parser.add_argument("--directions", action="store_true",
                             help="display read & write calls")
    dump_parser.add_argument("--content", action="store_true",
                             help="display buffers content")
    dump_parser.add_argument("--secrets", action="store_true",
                             help="display TLS secrets")
    dump_parser.add_argument("--write", action="store_true",
                             help="write TLS secrets to files")
    dump_parser.add_argument("--ssl_session_offset",
                             help="offset to the ssl_session_t structure")
    dump_parser.add_argument("--master_secret_offset",
                             help="offset to the master secret in an ssl_session_t structure")  # noqa: E501
    dump_parser.add_argument("--ssl_cipher_offset",
                             help="offset to the ssl_cipher structure in an ssl_session_t structure")  # noqa: E501
    dump_parser.add_argument("--client_hello_offset",
                             help="offset to the CLIENTHELLO_MSG structure in an ssl structure")  # noqa: E501
    dump_parser.add_argument("--client_random_offset",
                             help="offset to the client random in an CLIENTHELLO_MSG structure")  # noqa: E501
    dump_parser.set_defaults(func=tls_command)

    # Prepare the 'proxy' subcommand
    dump_parser = subparser.add_parser("proxy",
                                       help="Automatically intercept TLS connections")  # noqa: E501
    dump_parser.set_defaults(func=proxy_command)

    # Print the Help message when no arguments are provided
    if not argv:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Call the sub-command
    args = parser.parse_args(argv)
    args.func(args)
