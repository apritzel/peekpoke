# peekpoke
[![License](http://img.shields.io/badge/License-GPL-green.svg)](LICENSE.md)

peekpoke is a Linux command line tool to read from and write to system memory.
Its main use is to talk to hardware peripherals from userland: to read
or manipulate state, and to dump registers. It is similar, but more powerful
than devmem2: It supports accessing multiple memory locations in one call,
and can (hex-)dump a range of memory.

## Example usage

Read a single 32-bit MMIO register:

    $ peekpoke r.l 0x01c20000

Dump nine 32-bit registers, starting at address 0x1c2086c:

    $ peekpoke -b 0x01c20800 D.l 0x6c 9
    01c20860                              77777777
    01c20870  47444444 44444444  00000007 00000000
    01c20880  dfff5555 0001ffff  00000000 00000000

Program the Allwinner RSB controller to trigger a client register read:

    $ peekpoke -b 0x01f03400 w.l 0x2c 0x8b w.l 0x30 0x2d0000 w.l 0x10 3 w.l 0x0 0x80 p r.l 0x1c

## Hints / caveats

peekpoke uses the /dev/mem kernel interface to access physical memory, so
it is bound by its limitations:
- Typically access to DRAM is not allowed, so you can only dump device memory.
  `CONFIG_STRICT_DEVMEM` controls this behaviour, and is mostly set in
  distribution kernels.
- Modern kernels might prevent access to MMIO regions claimed by a driver
  (`CONFIG_IO_STRICT_DEVMEM`), in which case you can only access devices
  which do not have a driver (loaded). `/proc/iomem` lists those claimed
  regions.
- Access to /dev/mem is typically limited to root, with members of some group
  like kmem possibly having read-only access. That means that you have to run
  peekpoke either as root or via sudo, for it to be useful.

If the device to be accessed is clock or power gated, accesses may fail, or
write accesses might be ignored.
