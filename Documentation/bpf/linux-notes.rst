.. contents::
.. sectnum::

==========================
Linux implementation notes
==========================

This document provides more details specific to the Linux kernel implementation of the eBPF instruction set.

Byte swap instructions
======================

``BPF_FROM_LE`` and ``BPF_FROM_BE`` exist as aliases for ``BPF_TO_LE`` and ``BPF_TO_BE`` respectively.

Jump instructions
=================

``BPF_CALL | BPF_X | BPF_JMP`` (0x8d), where the helper function
integer would be read from a specified register, is not currently supported
by the verifier.  Any programs with this instruction will fail to load
until such support is added.

Maps
====

Linux only supports the 'map_val(map)' operation on array maps with a single element.

Linux uses an fd_array to store maps associated with a BPF program. Thus,
map_by_idx(imm) uses the fd at that index in the array.

Variables
=========

The following 64-bit immediate instruction specifies that a variable address,
which corresponds to some integer stored in the 'imm' field, should be loaded:

=========================  ======  ===  =========================================  ===========  ==============
opcode construction        opcode  src  pseudocode                                 imm type     dst type
=========================  ======  ===  =========================================  ===========  ==============
BPF_IMM | BPF_DW | BPF_LD  0x18    0x3  dst = var_addr(imm)                        variable id  data pointer
=========================  ======  ===  =========================================  ===========  ==============

On Linux, this integer is a BTF ID.

Legacy BPF Packet access instructions
=====================================

As mentioned in the `ISA standard documentation
<instruction-set.html#legacy-bpf-packet-access-instructions>`_,
Linux has special eBPF instructions for access to packet data that have been
carried over from classic BPF to retain the performance of legacy socket
filters running in the eBPF interpreter.

The instructions come in two forms: ``BPF_ABS | <size> | BPF_LD`` and
``BPF_IND | <size> | BPF_LD``.

These instructions are used to access packet data and can only be used when
the program context is a pointer to a networking packet.  ``BPF_ABS``
accesses packet data at an absolute offset specified by the immediate data
and ``BPF_IND`` access packet data at an offset that includes the value of
a register in addition to the immediate data.

These instructions have seven implicit operands:

* Register R6 is an implicit input that must contain a pointer to a
  struct sk_buff.
* Register R0 is an implicit output which contains the data fetched from
  the packet.
* Registers R1-R5 are scratch registers that are clobbered by the
  instruction.

These instructions have an implicit program exit condition as well. If an
eBPF program attempts access data beyond the packet boundary, the
program execution will be aborted.

``BPF_ABS | BPF_W | BPF_LD`` (0x20) means::

  R0 = ntohl(*(u32 *) ((struct sk_buff *) R6->data + imm))

where ``ntohl()`` converts a 32-bit value from network byte order to host byte order.

``BPF_IND | BPF_W | BPF_LD`` (0x40) means::

  R0 = ntohl(*(u32 *) ((struct sk_buff *) R6->data + src + imm))

Cache maintenance instructions
==============================

Linux extends the ``ATOMIC`` mode modifier of the ``STX`` instruction
class with a set of cache maintenance instructions. They allow BPF
programs to keep memory coherent with agents that do not participate in
the CPU cache coherency protocol, such as DMA engines on
non-cache-coherent interconnects, accelerators and devices sharing
memory with the CPU, or to control the point of persistence for
persistent and CXL memory.

Unlike the other atomic operations, cache maintenance instructions only
use the ``BPF_B`` size modifier (``{ATOMIC, B, STX}``). The 'src_reg'
field must be zero, no register is written, and the operation applies to
the whole implementation-defined cache maintenance block that contains
the byte addressed by ``dst_reg + offset``. Programs that need to
operate on a larger region iterate over it in steps of the cache
maintenance block size.

.. table:: Cache maintenance operations

  ===========  =====  =================================================
  imm          value  description
  ===========  =====  =================================================
  CACHE_INVAL  0x120  invalidate cache block to the point of coherency
  CACHE_CLEAN  0x130  write cache block back to the point of coherency
  CACHE_FLUSH  0x140  write back and invalidate cache block
  ===========  =====  =================================================

``{ATOMIC, B, STX}`` with 'imm' = CACHE_INVAL means::

  cache_inval(dst + offset)

After the instruction completes, subsequent reads of the block observe
the value in memory rather than a stale cached copy. An implementation
may write dirty data back before invalidating (for example, x86
``CLFLUSH`` implements ``CACHE_INVAL`` as write-back plus invalidate),
so a program must not rely on ``CACHE_INVAL`` discarding unwritten data.

``{ATOMIC, B, STX}`` with 'imm' = CACHE_CLEAN means::

  cache_clean(dst + offset)

Dirty data in the block is written back to the point of coherency. The
block may stay resident in the cache.

``{ATOMIC, B, STX}`` with 'imm' = CACHE_FLUSH means::

  cache_flush(dst + offset)

Dirty data in the block is written back to the point of coherency and
the block is then invalidated.

All three operations are self-ordering: the maintenance operation
completes before any subsequent memory access of the program executes,
so no separate memory barrier instruction is required.

Cache maintenance instructions are only available to privileged programs
(``CAP_PERFMON``), because the ability to evict specific cache lines is a
building block for cache-timing side channels. The addressed memory must
be writable; ``CACHE_INVAL`` may discard data that has not been written
back, so all three operations are treated as memory writes for the
purpose of verification.

Support is optional and architecture dependent. On architectures that do
not implement cache maintenance instructions the verifier rejects them
at load time.
