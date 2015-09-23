
## /* 32-bit ELF base types. */
## typedef __u32   Elf32_Addr;
## typedef __u16   Elf32_Half;
## typedef __u32   Elf32_Off;
## typedef __s32   Elf32_Sword;
## typedef __u32   Elf32_Word;
##
## /* 64-bit ELF base types. */
## typedef __u64   Elf64_Addr;
## typedef __u16   Elf64_Half;
## typedef __s16   Elf64_SHalf;
## typedef __u64   Elf64_Off;
## typedef __s32   Elf64_Sword;
## typedef __u32   Elf64_Word;
## typedef __u64   Elf64_Xword;
## typedef __s64   Elf64_Sxword;

const
  PT_NULL* = 0
  PT_LOAD* = 1
  PT_DYNAMIC* = 2
  PT_INTERP* = 3
  PT_NOTE* = 4
  PT_SHLIB* = 5
  PT_PHDR* = 6
  PT_TLS* = 7
  PT_LOOS* = 0x60000000
  PT_HIOS* = 0x6fffffff
  PT_LOPROC* = 0x70000000
  PT_HIPROC* = 0x7fffffff
  PT_GNU_EH_FRAME* = 0x6474e550
  PT_GNU_STACK* = PT_LOOS + 0x474e551

  ET_NONE* = 0
  ET_REL* = 1
  ET_EXEC* = 2
  ET_DYN* = 3
  ET_CORE* = 4
  ET_LOPROC* = 0xff00
  ET_HIPROC* = 0xffff

  DT_NULL* = 0
  DT_NEEDED* = 1
  DT_PLTRELSZ* = 2
  DT_PLTGOT* = 3
  DT_HASH* = 4
  DT_STRTAB* = 5
  DT_SYMTAB* = 6
  DT_RELA* = 7
  DT_RELASZ* = 8
  DT_RELAENT* = 9
  DT_STRSZ* = 10
  DT_SYMENT* = 11
  DT_INIT* = 12
  DT_FINI* = 13
  DT_SONAME* = 14
  DT_RPATH* = 15
  DT_SYMBOLIC* = 16
  DT_REL* = 17
  DT_RELSZ* = 18
  DT_RELENT* = 19
  DT_PLTREL* = 20
  DT_DEBUG* = 21
  DT_TEXTREL* = 22
  DT_JMPREL* = 23
  DT_ENCODING* = 32
  OLD_DT_LOOS* = 0x60000000
  DT_LOOS* = 0x6000000d
  DT_HIOS* = 0x6ffff000
  DT_VALRNGLO* =  0x6ffffd00
  DT_VALRNGHI* = 0x6ffffdff
  DT_ADDRRNGLO* = 0x6ffffe00
  DT_ADDRRNGHI* = 0x6ffffeff
  DT_VERSYM* =  0x6ffffff0
  DT_RELACOUNT* = 0x6ffffff9
  DT_RELCOUNT* = 0x6ffffffa
  DT_FLAGS_1* = 0x6ffffffb
  DT_VERDEF* = 0x6ffffffc
  DT_VERDEFNUM* = 0x6ffffffd
  DT_VERNEED* = 0x6ffffffe
  DT_VERNEEDNUM* = 0x6fffffff
  OLD_DT_HIOS* = 0x6fffffff
  DT_LOPROC* = 0x70000000
  DT_HIPROC* = 0x7fffffff

include private/elf32
include private/elf64
