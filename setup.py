# SPDX-License-Identifier: GPL-2.0+
# Guillaume Valadon <gvaladon@quarkslab.com>

from distutils.core import setup, Extension

setup(name="peetch",
      description="An eBPF playground",
      author="Guillaume Valadon",
      author_email="gvaladon@quarkslab.com",
      version="0.1.2",
      packages=["peetch"],
      package_data={"peetch": ["ebpf_programs/peetch_*.c"]},
      entry_points={"console_scripts": ["peetch=peetch:main"]},
      ext_modules=[Extension("peetch.utils_lib", sources=["peetch/c_utils/libssl.c"], libraries=["ssl"])],
      )
