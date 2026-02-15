HymoFS KPM module

This module ports the HymoFS kernel patch to a KernelPatch KPM module
for Android GKI 6.6.x. It keeps the original anonymous-fd ioctl control
interface and injects behavior via inline hooks.

Build:
  make KP_DIR=../KernelPatch KERNEL_SRC=/path/to/kernel
  # KERNEL_SRC auto-detects ../patch_workspace/android15-6.6/common when present

Load:
  Use APatch manager to load the generated .kpm file.

## License

- **Author's work** — Apache License 2.0 (Apache-2.0). When used as a kernel module, **GPL-2.0** applies for kernel compatibility.
- [LICENSE](LICENSE), [LICENSE-GPL-2.0](LICENSE-GPL-2.0), [NOTICE](NOTICE)
- SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
