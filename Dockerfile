# SPDX-License-Identifier: GPL-2.0+
# Guillaume Valadon <gvaladon@quarkslab.com>

FROM ubuntu:22.04

ENV TZ=Europe/Paris DEBIAN_FRONTEND=noninteractive
RUN echo 'PS1="quarkslab/peetch:\w# "' >> /root/.bashrc

# Install dependencies
RUN set -x && \
    PACKAGES="bison build-essential cmake flex git \
    libedit-dev libllvm11 llvm-11-dev libclang-11-dev python3 zlib1g-dev \
    libelf-dev libfl-dev python3-distutils python3-pip linux-headers-$(uname -r) \
    libssl-dev iproute2 tmux curl bc libelf-dev zip tshark curl" && \
    apt-get update && apt-get install -y $PACKAGES && \
    apt-get autoclean && apt-get --purge -y autoremove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Compile bcc
RUN git clone https://github.com/iovisor/bcc && cd bcc/ && mkdir build && \
    cd build && cmake .. && make install && cd src && make install && rm -rf /bcc/

# Install peetch
COPY . /peetch
RUN cd /peetch && pip install --upgrade pip && pip install -r requirements.txt && \
    pip install . && rm -rf /peetch