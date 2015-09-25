
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

import posix, pegs, strutils, ../ptrace/ptrace/ptrace

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
  DT_GNU_HASH* = 0x6ffffef5

  STT_NOTYPE* = 0
  STT_OBJECT* = 1
  STT_FUNC* = 2
  STT_SECTION* = 3
  STT_FILE* = 4
  STT_COMMON* = 5
  STT_TLS* = 6
  STT_NUM* = 7
  STT_LOOS* = 10
  STT_GNU_IFUNC* = 10
  STT_HIOS* = 12
  STT_LOPROC* = 13
  STT_HIPROC* = 15

include private/elf32
include private/elf64


when hostCPU == "i386":
  type
    Elf_Ehdr = Elf32_Ehdr
    Elf_Phdr = Elf32_Phdr
    Elf_Dyn = Elf32_Dyn
    Elf_Sym = Elf32_Sym
else:
  type
    Elf_Ehdr = Elf64_Ehdr
    Elf_Phdr = Elf64_Phdr
    Elf_Dyn = Elf64_Dyn
    Elf_Sym = Elf64_Sym

type
  LinkMap* = object
    l_addr*: cuint
    l_name*: cstring
    l_ld*: ptr Elf_Dyn
    l_next*: ptr LinkMap
    l_prev*: ptr LinkMap


let
  freeSpaceEntry = peg(r"{\w+}'-'(\w+)\s[rwxp-]+\s\d+\s'00:00'")
  elfHeaderAddress: clong = 0x08048000

var
  nchains: clong
  symtab, strtab: culong

proc getFreeSpaceAddr*(p: int): int =
  var
    fp: File
    filename = "/proc/" & $p & "/maps"
    line: string

  fp = open(filename, fmRead)
  if fp.isNil:
    raise newException(IOError, "Unable to open " & filename & " for reading")

  while not endOfFile(fp):
    line = readLine(fp)
    echo line
    if line =~ freeSpaceEntry:
      result = parseHexInt(matches[0])
      break
  close(fp)

proc getLinkMap*(p: int): LinkMap =
  var
    ehdr: Elf_Ehdr
    phdr: Elf_Phdr
    dyn: Elf_Dyn
    got: uint32
    phdr_addr, dyn_addr, map_addr: clong

  attach(p)

  getData(p, elfHeaderAddress, addr ehdr, sizeof(ehdr))

  phdr_addr = elfHeaderAddress + ehdr.e_phoff.clong
  getData(p, phdr_addr, addr phdr, sizeof(phdr))

  while phdr.p_type != PT_DYNAMIC:
    phdr_addr.inc(sizeof(phdr))
    getData(p, phdr_addr, addr phdr, sizeof(phdr))

  getData(p, phdr.p_vaddr.clong, addr dyn, sizeof(dyn))
  dyn_addr = phdr.p_vaddr.clong


  while dyn.d_tag != DT_PLTGOT:
    dyn_addr = dyn_addr + sizeof(dyn)
    getData(p, dyn_addr, addr dyn, sizeof(dyn))

  got = dyn.d_un.d_ptr
  inc(got, WORD_SIZE)

  map_addr = getData(p, got.clong)

  getData(p, map_addr, addr result, sizeof(LinkMap))
  discard detach(p)

proc getSymInfo*(p: Pid, map: LinkMap) =
  var
    dyn: Elf_Dyn
    dyn_addr: clong

  dyn_addr = cast[clong](map.l_ld)

  attach(p)
  getData(p, dyn_addr, addr dyn, sizeof(dyn))

  while dyn.d_tag != DT_NULL:
    if dyn.d_tag == DT_SYMTAB:
      symtab = dyn.d_un.d_ptr
    elif dyn.d_tag == DT_STRTAB:
      strtab = dyn.d_un.d_ptr
    elif dyn.d_tag == DT_GNU_HASH:
      nchains = getData(p, clong(dyn.d_un.d_ptr + map.l_addr + WORD_SIZE))
    else:
      discard

    dyn_addr.inc(sizeof(Elf_Dyn))
    getData(p, dyn_addr, addr dyn, sizeof(dyn))

  detach(p)

proc findSym*(p: Pid, map: LinkMap, name: cstring): culong =
  result = 0
  var
    sym: Elf_Sym
    str: string
  echo nchains
  attach(p)
  for i in 0..nchains-1:

    getData(p, symtab.clong + clong(i * sizeof(Elf_Sym)), addr sym, sizeof(sym))

    str = getString(p, clong(strtab + sym.st_name))
    echo str
    if sym.st_info.int != STT_FUNC:
      continue


    echo str
    if str == name:
      result = map.l_addr + sym.st_value
      break
  discard detach(p)



when isMainModule:
  import os

  let pid: Pid = parseInt(paramStr(1))

  let map = getLinkMap(pid)
  getSymInfo(pid, map)

  echo findSym(pid, map, "frame_dummy")
