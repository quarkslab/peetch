# SPDX-License-Identifier: GPL-2.0+
# Guillaume Valadon <gvaladon@quarkslab.com>

import ctypes
import os
import os.path
import sys

# Identify the library path
dirname = os.path.dirname(__file__)
UTILS_LIB_PATH = None
for root, dirs, files in os.walk(dirname):
    for file in files:
        if file.startswith("utils_lib") and file.endswith(".so"):
            UTILS_LIB_PATH = os.path.join(root, file)
            break


class LIBSSLOffsets(ctypes.Structure):
    _fields_ = [("ssl_session", ctypes.c_uint64),
                ("ssl_cipher", ctypes.c_uint64),
                ("master_secret", ctypes.c_uint64)]


if UTILS_LIB_PATH:
    libssl_offset = ctypes.CDLL(UTILS_LIB_PATH)
    libssl_offset.libssl_offsets.argstypes = [ctypes.c_char_p, ctypes.c_uint16]
    libssl_offset.libssl_offsets.restype = LIBSSLOffsets

    def get_offsets(address_ipv4=b"1.1.1.1", port=443):
        # Retrieve offsets inside SSL structures
        raw_offsets = libssl_offset.libssl_offsets(address_ipv4, port)
        return (raw_offsets.ssl_session,
                raw_offsets.ssl_cipher,
                raw_offsets.master_secret)
else:
    print("ERROR: cannot find the utils_lib dynamic library!", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    print(["0x%x" % offset for offset in get_offsets()])
