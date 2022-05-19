# SPDX-License-Identifier: GPL-2.0+
# Guillaume Valadon <gvaladon@quarkslab.com>

from setuptools import setup

setup(name="peetch",
      description="An eBPF playground",
      author="Guillaume Valadon",
      author_email="gvaladon@quarkslab.com",
      version="0.1",
      packages=["peetch"],
      scripts=["bin/peetch"],
      package_data={"peetch": ["ebpf_programs/peetch_*.c"]},
      )
