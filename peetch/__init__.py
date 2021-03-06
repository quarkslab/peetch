# SPDX-License-Identifier: GPL-2.0+
# Guillaume Valadon <gvaladon@quarkslab.com>

import argparse
import atexit
import ctypes as ct
import binascii
import os
import peetch.utils
import socket
import struct
import sys
import time

from bcc import BPF
import pyroute2
from scapy.all import Ether, wrpcapng, hexdump


EBPF_PROGRAMS_DIRNAME = os.path.join(os.path.dirname(__file__),
                                     "ebpf_programs/")
BPF_DUMP_PROGRAM_FILENAME = "%s/peetch_kprobes.c" % EBPF_PROGRAMS_DIRNAME
BPF_DUMP_PROGRAM_SOURCE = open(BPF_DUMP_PROGRAM_FILENAME).read()
BPF_TLS_PROGRAM_FILENAME = "%s/peetch_uprobes.c" % EBPF_PROGRAMS_DIRNAME
BPF_TLS_PROGRAM_SOURCE = open(BPF_TLS_PROGRAM_FILENAME).read()
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


def exit_handler(interface, filename, bpf_handler):
    """
    Exit nicely
    """
    time.sleep(0.01)
    bpf_handler.detach_kprobe(event="security_sk_classify_flow",
                              fn_name="kprobe_security_sk_classify_flow")
    unload_classifier(interface)
    if filename:
        wrpcapng(filename, PACKETS_CAPTURED)


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
    atexit.register(exit_handler, args.interface, args.write, bpf_handler)

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


def tls_command(args):
    # Process arguments
    if args.content:
        args.directions = True

    directions_bool = "1"
    if args.directions:
        directions_bool = "0"

    # Get SSL structures offsets
    offsets = [str(offset) for offset in peetch.utils.get_offsets()]
    ssl_session_offset, ssl_cipher_offset, master_secret_offset = offsets

    if ssl_session_offset == ssl_cipher_offset and \
       ssl_cipher_offset == master_secret_offset and master_secret_offset == 0:
        print("ERROR: cannot guess SSL offsets!", file=sys.stderr)
        sys.exit(1)

    if ssl_session_offset:
        ssl_session_offset = args.ssl_session_offset

    if ssl_cipher_offset:
        ssl_cipher_offset = args.ssl_cipher_offset

    if master_secret_offset:
        master_secret_offset = args.master_secret_offset

    # Compile eBPF programs
    ebpf_programs = BPF_TLS_PROGRAM_SOURCE.replace("DIRECTIONS",
                                                   directions_bool)
    ebpf_programs = ebpf_programs.replace("SSL_SESSION_OFFSET",
                                          ssl_session_offset)
    ebpf_programs = ebpf_programs.replace("MASTER_SECRET_OFFSET",
                                          master_secret_offset)
    ebpf_programs = ebpf_programs.replace("SSL_CIPHER_OFFSET",
                                          ssl_cipher_offset)
    bpf_handler = BPF(text=ebpf_programs)

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
        bpf_map_tls_information = bpf_handler["tls_information_cache"]
        for pid, tls_info in bpf_map_tls_information.items_lookup_batch():
            if pid == tls_event.pid:
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
                fd = open("%d-master_secret.log" % pid, "w")
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
                             default="0x510",
                             help="offset to the ssl_session_t structure")
    dump_parser.add_argument("--master_secret_offset",
                             default="80",
                             help="offset to the master secret in an ssl_session_t structure")  # noqa: E501
    dump_parser.add_argument("--ssl_cipher_offset",
                             default="0x1f8",
                             help="offset to the ssl_cipher structure in an ssl_session_t structure")  # noqa: E501
    dump_parser.set_defaults(func=tls_command)

    # Print the Help message when no arguments are provided
    if not argv:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Call the sub-command
    args = parser.parse_args(argv)
    args.func(args)
