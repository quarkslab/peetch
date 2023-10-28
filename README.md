# peetch

`peetch` is a collection of tools aimed at experimenting with different aspects of eBPF to bypass TLS protocol protections.

Currently, peetch includes two subcommands. The first called `dump` aims to sniff network traffic by associating information about the source process with each packet. The second called `tls` allows to identify processes using OpenSSL to extract cryptographic keys.

Combined, these two commands make it possible to decrypt TLS exchanges recorded in the PCAPng format.

## Installation

`peetch` relies on several dependencies including [bcc](https://github.com/iovisor/bcc) and [Scapy](https://github.com/secdev/scapy). A Docker image can be easily built in order to easily test `peetch` using the following command:

```shell
docker build -t quarkslab/peetch .
```

## Commands Walk Through

The following examples assume that you used the following command to enter the Docker image and launch examples within it:

```shell
docker run --privileged --network host --mount type=bind,source=/sys,target=/sys --mount type=bind,source=/proc,target=/proc --rm -it quarkslab/peetch
```

### `dump`

This sub-command gives you the ability to sniff packets using an eBPF TC classifier and to retrieve the corresponding PID and process names with:

```shell
peetch dump
curl/1289291 - Ether / IP / TCP 10.211.55.10:53052 > 208.97.177.124:https S / Padding
curl/1289291 - Ether / IP / TCP 208.97.177.124:https > 10.211.55.10:53052 SA / Padding
curl/1289291 - Ether / IP / TCP 10.211.55.10:53052 > 208.97.177.124:https A / Padding
curl/1289291 - Ether / IP / TCP 10.211.55.10:53052 > 208.97.177.124:https PA / Raw / Padding
curl/1289291 - Ether / IP / TCP 208.97.177.124:https > 10.211.55.10:53052 A / Padding
```

Note that as of today, `dump` will only capture IPv4 based TCP segments.

For convenience, the captured packets can be store to PCAPng along with process information using `--write`:

```shell
peetch dump --write peetch.pcapng
^C
```

This PCAPng can easily be manipulated with Wireshark or Scapy:

```python
scapy
>>> l = rdpcap("peetch.pcapng")
>>> l[0]
<Ether  dst=00:1c:42:00:00:18 src=00:1c:42:54:f3:34 type=IPv4 |<IP  version=4 ihl=5 tos=0x0 len=60 id=11088 flags=DF frag=0 ttl=64 proto=tcp chksum=0x4bb1 src=10.211.55.10 dst=208.97.177.124 |<TCP  sport=53054 dport=https seq=631406526 ack=0 dataofs=10 reserved=0 flags=S window=64240 chksum=0xc3e9 urgptr=0 options=[('MSS', 1460), ('SAckOK', b''), ('Timestamp', (1272423534, 0)), ('NOP', None), ('WScale', 7)] |<Padding  load='\x00\x00' |>>>>
>>> l[0].comment
b'curl/1289909'
```

### `tls`

This sub-command aims at identifying process that uses OpenSSL and makes it is to dump several things like plaintext and secrets.

By default, `peetch tls` will only display one line per process, the `--directions` argument makes it possible to display the exchanged messages:

```shell
peetch tls --directions
<- curl (1291078) 208.97.177.124/443 TLS1.2 ECDHE-RSA-AES128-GCM-SHA256
-> curl (1291078) 208.97.177.124/443 TLS1.2 ECDHE-RSA-AES128-GCM-SHA256
```

Displaying OpenSSL buffer content is achieved with `--content`.

```shell
peetch tls --content
<- curl (1290608) 208.97.177.124/443 TLS1.2 ECDHE-RSA-AES128-GCM-SHA256

   0000  47 45 54 20 2F 20 48 54 54 50 2F 31 2E 31 0D 0A  GET / HTTP/1.1..
   0010  48 6F 73 74 3A 20 77 77 77 2E 70 65 72 64 75 2E  Host: www.perdu.
   0020  63 6F 6D 0D 0A 55 73 65 72 2D 41 67 65 6E 74 3A  com..User-Agent:
   0030  20 63 75 72 6C 2F 37 2E 36 38 2E 30 0D 0A 41 63   curl/7.68.0..Ac

-> curl (1290608) 208.97.177.124/443 TLS1.2 ECDHE-RSA-AES128-GCM-SHA256

   0000  48 54 54 50 2F 31 2E 31 20 32 30 30 20 4F 4B 0D  HTTP/1.1 200 OK.
   0010  0A 44 61 74 65 3A 20 54 68 75 2C 20 31 39 20 4D  .Date: Thu, 19 M
   0020  61 79 20 32 30 32 32 20 31 38 3A 31 36 3A 30 31  ay 2022 18:16:01
   0030  20 47 4D 54 0D 0A 53 65 72 76 65 72 3A 20 41 70   GMT..Server: Ap
```

The `--secrets` arguments will display TLS Master Secrets extracted from memory. The following example leverages `--write` to write master secrets to simplify decrypting TLS messages with Scapy:

```shell
$ (sleep 5; curl https://www.perdu.com/?name=highly%20secret%20information --tls-max 1.2 --http1.1 --tlsv1.2) &

# peetch tls --write &
curl (1293232) 208.97.177.124/443 TLS1.2 ECDHE-RSA-AES128-GCM-SHA256

# peetch dump --write traffic.pcapng
^C

# Add the master secret to a PCAPng file
$ editcap --inject-secrets tls,1293232-master_secret.log traffic.pcapng traffic-ms.pcapng

$ scapy
>>> load_layer("tls")
>>> conf.tls_session_enable = True
>>> l = rdpcap("traffic-ms.pcapng")
>>> l[13][TLS].msg
[<TLSApplicationData  data='GET /?name=highly%20secret%20information HTTP/1.1\r\nHost: www.perdu.com\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n' |>]
```

## Limitations

By design, `peetch` only supports OpenSSL and TLS 1.2.
