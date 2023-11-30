# SPDX-License-Identifier: GPL-2.0+
# Guillaume Valadon <gvaladon@quarkslab.com>

import asyncio
import binascii
import ctypes as ct
import socket
import struct
import sys
import time

from scapy.all import sniff, IP, TCP, conf

import peetch.globals


def retrieve_client_information(bpf_handler, port_src):
    """
    Get client information from eBPF maps
    """

    process_name, process_pid, ip_dst, port_dst = [None] * 4
    bpf_map_destination_cache = bpf_handler["destination_cache"]

    destination_key_to_delete = None

    for destination_key, destination_data in bpf_map_destination_cache.items_lookup_batch():  # noqa: E501
        process_pid = destination_data.pid
        process_name = destination_data.name.decode("ascii", "replace")

        # Retrieve destination IP and port
        address_packed = struct.pack("I", destination_data.ip)
        ip_dst = socket.inet_ntop(socket.AF_INET, address_packed)
        port_dst = socket.ntohs(destination_data.port)

        if socket.ntohs(destination_key.value) == port_src:
            ct_array = ct.c_uint16 * 1
            destination_key_to_delete = ct_array(destination_key)
            break

    if destination_key_to_delete:
        bpf_map_destination_cache.items_delete_batch(destination_key_to_delete)

    return process_name, process_pid, ip_dst, port_dst


def retrieve_tls_information(bpf_handler, process_pid):
    """
    Get TLS information from eBPF maps
    """
    tls_version, ciphersuite, client_random, master_secret = [None] * 4

    retries = 5
    pid_to_delete = None
    bpf_map_tls_information = bpf_handler["tls_information_cache"]
    while pid_to_delete is None and retries:
        retries -= 1
        for pid, tls_info in bpf_map_tls_information.items_lookup_batch():
            if pid.value == process_pid:
                ciphersuite = tls_info.ciphersuite.decode("ascii", "ignore")
                master_secret = binascii.hexlify(tls_info.master_secret)
                master_secret = master_secret.decode("ascii", "ignore")
                client_random = binascii.hexlify(tls_info.client_random)
                client_random = client_random.decode("ascii", "ignore")
                tls_version = (tls_info.tls_version & 0xF) - 1
                if len(ciphersuite):
                    ct_array = ct.c_uint * 1
                    pid_to_delete = ct_array(pid)
                    break
        #time.sleep(0.005)

    # Delete pid from the eBPF map
    if pid_to_delete:
        bpf_map_tls_information.items_delete_batch(pid_to_delete)

    return tls_version, ciphersuite, client_random, master_secret


async def dots():
    """
    print dots
    """
    while True:
        await asyncio.sleep(0.5)
        print(".", end="", flush=True)


def decrypt_messages(tls_information, packets):
    """
    Decrypt and display messages
    """

    tls_version = tls_information.get("version", sys.maxsize)
    if tls_version < 3:
        for p in sniff(offline=packets):
            if TLSApplicationData in p:  # noqa: F821
                print()
                p[TLSApplicationData].show()  # noqa: F821


async def handle_client(local_reader, local_writer):
    """
    Proxy a new client connection
    """

    # Retrieve source IP and port used to connect to the proxy
    ip_src, port_src = local_reader._transport.get_extra_info("peername")

    # Retrieve process information, and destination IP and port
    tmp = retrieve_client_information(peetch.globals.BPF_HANDLER, port_src)
    process_name, process_pid, ip_dst, port_dst = tmp

    if process_name is None:
        print("[!] Did not find the real destination")
        local_writer.close()
        return

    print("", flush=True)
    print(f"\r[+] Intercepting traffic from {process_name}/{process_pid}", end="")  # noqa: E501
    print(f" to {ip_dst}/{port_dst} via {ip_src}/{port_src}")

    try:
        # Connect to the real destination and copy data between sockets
        tmp = await asyncio.open_connection(ip_dst, port_dst)
        remote_reader, remote_writer = tmp
        pipe1 = pipe(local_reader, remote_writer, process_pid,
                     "-->", ip_src, ip_dst, port_src, port_dst)
        pipe2 = pipe(remote_reader, local_writer, process_pid,
                     "<--", ip_dst, ip_src, port_dst, port_src)
        await asyncio.gather(pipe1, pipe2)

        # Decrypt and display TLS messages
        decrypt_messages(peetch.globals.TLS_INFORMATION,
                         peetch.globals.PACKETS_CAPTURED)

        # Reset global variables
        conf.tls_nss_keys = {}
        peetch.globals.TLS_INFORMATION = {}
        peetch.globals.PACKETS_CAPTURED = []
    except ConnectionResetError as e:
        print(f"   {e}")
    finally:
        local_writer.close()


async def pipe(reader, writer, pid, direction, ip_src, ip_dst, port_src, port_dst):  # noqa: E501
    """"
    Copy data from one socket to another and retrieve TLS information
    Inspired by https://stackoverflow.com/a/46422554
    """

    try:
        while not reader.at_eof():
            data = await reader.read(8192)
            if not len(data):
                continue

            # Rebuild the IP packet
            tls_record = IP(dst=ip_dst, src=ip_src)
            tls_record /= TCP(dport=port_dst, sport=port_src)
            tls_record /= TLS(data)  # noqa: F821
            peetch.globals.PACKETS_CAPTURED += [tls_record]

            # Display a short summary
            sprintf_fmt = "%IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport% %IP.proto%"  # noqa: E501
            summary = tls_record.sprintf(sprintf_fmt)
            print(f"    {direction} {summary}")

            # Copy data to the other socket
            writer.write(data)

            # Get and store TLS information
            tls_version, ciphersuite, client_random, master_secret = retrieve_tls_information(peetch.globals.BPF_TLS_HANDLER, pid)  # noqa: E501
            if ciphersuite:
                if tls_version < 3:
                    client_random_bytes = binascii.unhexlify(client_random)
                    master_secret_bytes = binascii.unhexlify(master_secret)
                    conf.tls_nss_keys = {"CLIENT_RANDOM": {client_random_bytes: master_secret_bytes}}  # noqa: E501
                    peetch.globals.TLS_INFORMATION = {"version": tls_version,
                                                      "ciphersuite": ciphersuite}  # noqa: E501
    finally:
        writer.close()


async def tcp_proxy():
    """
    async TCP proxy
    """
    server = await asyncio.start_server(handle_client, "127.0.0.1", 2807)
    await server.serve_forever()


async def all_tasks(debug):
    """
    all proxy tasks
    """
    tasks = [tcp_proxy()]
    if debug:
        tasks += [dots()]
    await asyncio.gather(*tasks)
